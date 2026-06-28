//! Mutual-TLS round-trip test for the mesh work-queue listener.
//!
//! `GET/PATCH /v1/networks` are served over mutual TLS and carry no JWT — the
//! handshake + the stamped `ServiceIdentity` are the `SERVICE` authentication. These
//! tests mint a throwaway mesh CA with `rcgen`, wrap the
//! [`wardnet_tenants::api::reconcile`] router in a `tokio_rustls::TlsAcceptor`, and
//! drive it with a `reqwest` client
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
use wardnet_common::contract::{Entitlement, SubscriptionStatus};
use wardnet_common::mtls::ExpectedPeer;
use wardnet_common::{mtls, serve};
use wardnet_subscriptions::Subscription;
use wardnet_tenants::api::reconcile;
use wardnet_tenants::repository::tenant::Tenant;
use wardnet_tenants::state::AppState;
mod common;
use common::{build_state, daemon_keypair};

const SEED: u8 = 5;
const REGION: &str = "use1";
const SERVER_NAME: &str = "tenants.mesh.local";
/// SPIFFE ids for the mesh leaves (URI SAN only — no DNS SAN).
const TENANTS_SPIFFE: &str = "spiffe://wardnet.test/dev/global/tenants";
const DDNS_SPIFFE: &str = "spiffe://wardnet.test/dev/use1/ddns";

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

    fn leaf(&self, spiffe_id: &str, eku: ExtendedKeyUsagePurpose) -> Leaf {
        let key = KeyPair::generate().expect("generate leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.subject_alt_names = vec![rcgen::SanType::URI(
            spiffe_id.try_into().expect("valid spiffe id"),
        )];
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
    let now = chrono::Utc::now();
    store.seed_tenant(Tenant {
        id: "t1".to_string(),
        email: "t1@example.com".to_string(),
        created_at: now,
        deregistered_at: None,
    });
    store.seed_subscription(Subscription {
        id: "sub-t1".to_string(),
        tenant_id: "t1".to_string(),
        status: SubscriptionStatus::Active,
        entitlement: Entitlement {
            max_networks: 5,
            max_daemons: 5,
        },
        trial_expires_at: None,
        current_period_end: None,
        created_at: now,
        updated_at: now,
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
    let router = reconcile::router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept mesh conn");
        match acceptor.accept(stream).await {
            Ok(tls) => {
                // Mirror serve_mesh: parse the peer SPIFFE id and stamp it.
                let peer_id = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| mtls::peer_spiffe_id(certs).ok())
                    .expect("peer SPIFFE id");
                let router = router.layer(Extension(ServiceIdentity::from(peer_id)));
                let _ = serve::connection(tls, router, peer).await;
            }
            Err(e) => tracing::debug!(error = %e, "mesh handshake rejected"),
        }
    });
    addr
}

fn mesh_client(client: &Leaf, ca_pem: &str, addr: SocketAddr) -> reqwest::Client {
    let config = mtls::client_config_from_pem(
        client.cert_pem.as_bytes(),
        client.key_pem.as_bytes(),
        ca_pem.as_bytes(),
        ExpectedPeer::new("tenants", "global"),
    )
    .expect("build mesh client config");
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .resolve(SERVER_NAME, addr)
        .build()
        .expect("build mesh reqwest client")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn reconcile_get_then_patch_over_mtls() {
    mtls::install_crypto_provider();
    let ca = MeshCa::new();
    let server = ca.leaf(TENANTS_SPIFFE, ExtendedKeyUsagePurpose::ServerAuth);
    let client = ca.leaf(DDNS_SPIFFE, ExtendedKeyUsagePurpose::ClientAuth);

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
async fn reaper_deprovisioned_patch_is_idempotent() {
    mtls::install_crypto_provider();
    let ca = MeshCa::new();
    let server = ca.leaf(TENANTS_SPIFFE, ExtendedKeyUsagePurpose::ServerAuth);
    let client = ca.leaf(DDNS_SPIFFE, ExtendedKeyUsagePurpose::ClientAuth);

    let (state, network_id) = state_with_network().await;
    // Move the network to `deprovisioning` (the cancel cascade the network reactor runs).
    state
        .tenants()
        .deprovision_networks_for("t1")
        .await
        .unwrap();

    let addr = spawn_mesh(state, &server, ca.root_pem()).await;
    let http = mesh_client(&client, ca.root_pem(), addr);
    let url = format!("https://{SERVER_NAME}/v1/networks/{network_id}");
    let body = serde_json::json!({ "provisioningState": "deprovisioned" });

    // First PATCH deletes the row.
    let resp = http.patch(&url).json(&body).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
    // A retried reaper tick (row already gone) is still success, not 409.
    let resp = http.patch(&url).json(&body).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn mesh_rejects_client_cert_from_a_foreign_ca() {
    mtls::install_crypto_provider();
    let server_ca = MeshCa::new();
    let foreign_ca = MeshCa::new();
    let server = server_ca.leaf(TENANTS_SPIFFE, ExtendedKeyUsagePurpose::ServerAuth);
    let foreign_client = foreign_ca.leaf(DDNS_SPIFFE, ExtendedKeyUsagePurpose::ClientAuth);

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
