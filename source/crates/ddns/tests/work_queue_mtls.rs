//! Mutual-TLS round-trip test for [`TenantsWorkQueue`] (the *client* side of the
//! mesh work-queue). Stands up a throwaway mesh CA with `rcgen`, serves a minimal
//! canned `GET/PATCH /v1/networks` router behind a `tokio_rustls::TlsAcceptor` with
//! an IP-SAN server cert, then drives it through the real [`wardnet_common::mtls::MeshClient`].
//!
//! `#[ignore]`'d — it binds a real TCP listener and completes a TLS handshake.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::routing::{get, patch};
use axum::{Json, Router};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use wardnet_common::mtls::{self, MeshClient};
use wardnet_common::serve;
use wardnet_ddns::work_queue::{TenantsWorkQueue, WorkQueue};

const REGION: &str = "use1";

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

    fn leaf(&self, san: SanType, eku: ExtendedKeyUsagePurpose) -> Leaf {
        let key = KeyPair::generate().expect("generate leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.subject_alt_names = vec![san];
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

/// Serve a canned mesh router behind a `TlsAcceptor`, looping over connections.
async fn spawn_mesh(server: &Leaf, ca_pem: &str) -> SocketAddr {
    let server_config = mtls::server_config_from_pem(
        server.cert_pem.as_bytes(),
        server.key_pem.as_bytes(),
        ca_pem.as_bytes(),
    )
    .expect("build mesh server config");
    let acceptor = TlsAcceptor::from(server_config);

    let router = Router::new()
        .route(
            "/v1/networks",
            get(|| async {
                Json(serde_json::json!([{
                    "id": "n1",
                    "slug": "happy",
                    "display_name": "Happy",
                    "region": REGION,
                    "provisioning_state": "provisioning",
                    "created_at": "2026-06-16T00:00:00Z"
                }]))
            }),
        )
        .route(
            "/v1/networks/{id}",
            patch(|| async { axum::http::StatusCode::NO_CONTENT }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    let _ = serve::connection(tls, router, peer).await;
                }
            });
        }
    });
    addr
}

#[tokio::test]
#[ignore = "binds a TCP listener + completes a TLS handshake"]
async fn list_then_transition_round_trip_over_mtls() {
    mtls::install_crypto_provider();
    let ca = MeshCa::new();
    let server = ca.leaf(
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let client = ca.leaf(
        SanType::DnsName("ddns.mesh.local".try_into().unwrap()),
        ExtendedKeyUsagePurpose::ClientAuth,
    );

    let addr = spawn_mesh(&server, &ca.root_pem).await;

    let mesh = MeshClient::new(
        client.cert_pem.as_bytes(),
        client.key_pem.as_bytes(),
        ca.root_pem.as_bytes(),
    )
    .expect("build mesh client");
    let work = TenantsWorkQueue::new(mesh, format!("https://127.0.0.1:{}", addr.port()));

    // GET the provisioning work queue.
    let networks = work
        .list("provisioning", REGION, None, 100)
        .await
        .expect("list over mTLS");
    assert_eq!(networks.len(), 1);
    assert_eq!(networks[0].id, "n1");
    assert_eq!(networks[0].slug, "happy");

    // PATCH it to active.
    work.transition("n1", "active")
        .await
        .expect("transition over mTLS");
}
