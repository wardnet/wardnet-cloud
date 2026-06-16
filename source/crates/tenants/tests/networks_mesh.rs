//! Mutual-TLS round-trip test for the mesh work-queue listener.
//!
//! `GET/PATCH /v1/networks` are served over mutual TLS and carry no JWT — the
//! handshake + the stamped `ServiceIdentity` are the `SERVICE` authentication. These
//! tests mint a throwaway mesh CA with `rcgen`, wrap [`wardnet_tenants::mesh`]'s
//! router in a `tokio_rustls::TlsAcceptor`, and drive it with a `reqwest` client
//! configured for client-certificate auth.

use std::net::SocketAddr;

use axum::Extension;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use wardnet_common::auth::ServiceIdentity;
use wardnet_common::{mtls, serve};
use wardnet_tenants::mesh::mesh_router;
use wardnet_tenants::repository::tenant::{Entitlement, SubscriptionStatus, Tenant};
use wardnet_tenants::state::AppState;
use wardnet_tenants::test_helpers::{build_state, daemon_keypair};

const SEED: u8 = 5;
const REGION: &str = "use1";
const SERVER_NAME: &str = "tenants.mesh.local";

// ── Throwaway mesh PKI ──────────────────────────────────────────────────────────

struct MeshCa {
    issuer: Issuer<'static, KeyPair>,
    root_pem: String,
}

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

// ── Fixtures ────────────────────────────────────────────────────────────────────

/// Build a state with one `provisioning` network in [`REGION`]; returns
/// `(state, network_id)`.
async fn state_with_network() -> (AppState, String) {
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

/// Spawn the mesh router behind a `TlsAcceptor` on an ephemeral port, accepting one
/// connection (which may carry multiple keep-alive requests). Mirrors `serve_mesh`,
/// including the per-connection `ServiceIdentity` stamp.
async fn spawn_mesh(state: AppState, server: &Leaf, ca_pem: &str) -> SocketAddr {
    let server_config = mtls::server_config_from_pem(
        server.cert_pem.as_bytes(),
        server.key_pem.as_bytes(),
        ca_pem.as_bytes(),
    )
    .expect("build mesh server config");
    let acceptor = TlsAcceptor::from(server_config);
    let router = mesh_router(state).layer(Extension(ServiceIdentity {
        subject: String::new(),
    }));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept mesh conn");
        match acceptor.accept(stream).await {
            Ok(tls) => {
                let _ = serve::connection(tls, router, peer).await;
            }
            Err(e) => tracing::debug!(error = %e, "mesh handshake rejected"),
        }
    });
    addr
}

fn mesh_client(client: &Leaf, ca_pem: &str, addr: SocketAddr) -> reqwest::Client {
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn reconcile_get_then_patch_over_mtls() {
    mtls::install_crypto_provider();
    let ca = MeshCa::new();
    let server = ca.leaf(SERVER_NAME, ExtendedKeyUsagePurpose::ServerAuth);
    let client = ca.leaf("ddns.mesh.local", ExtendedKeyUsagePurpose::ClientAuth);

    let (state, network_id) = state_with_network().await;
    let addr = spawn_mesh(state, &server, ca.root_pem()).await;
    let http = mesh_client(&client, ca.root_pem(), addr);

    // GET the provisioning work queue.
    let resp = http
        .get(format!(
            "https://{SERVER_NAME}/v1/networks?provisioningState=provisioning&region={REGION}"
        ))
        .send()
        .await
        .expect("mesh GET should complete over mTLS");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let networks: serde_json::Value = resp.json().await.unwrap();
    let arr = networks.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], serde_json::json!(network_id));

    // PATCH it to active (provisioner reporting success).
    let resp = http
        .patch(format!("https://{SERVER_NAME}/v1/networks/{network_id}"))
        .json(&serde_json::json!({ "provisioningState": "active" }))
        .send()
        .await
        .expect("mesh PATCH should complete");
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn mesh_rejects_client_cert_from_a_foreign_ca() {
    mtls::install_crypto_provider();
    let server_ca = MeshCa::new();
    let foreign_ca = MeshCa::new();
    let server = server_ca.leaf(SERVER_NAME, ExtendedKeyUsagePurpose::ServerAuth);
    let foreign_client =
        foreign_ca.leaf("attacker.mesh.local", ExtendedKeyUsagePurpose::ClientAuth);

    let (state, _id) = state_with_network().await;
    let addr = spawn_mesh(state, &server, server_ca.root_pem()).await;

    // Trusts the correct server CA (so the server cert verifies) but presents a
    // foreign client identity the server's verifier rejects.
    let http = mesh_client(&foreign_client, server_ca.root_pem(), addr);
    let result = http
        .get(format!(
            "https://{SERVER_NAME}/v1/networks?provisioningState=provisioning&region={REGION}"
        ))
        .send()
        .await;
    assert!(
        result.is_err(),
        "a client cert from a foreign CA must fail the mTLS handshake"
    );
}
