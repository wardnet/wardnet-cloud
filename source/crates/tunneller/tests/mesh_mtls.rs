//! Mutual-TLS round-trip tests for the mesh plane: the inter-node forward link and
//! the Tenants resolver client. Both stand up a throwaway mesh CA with `rcgen`.
//!
//! `#[ignore]`'d — they bind real TCP listeners and complete TLS handshakes.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use wardnet_common::mtls::{self, ExpectedPeer, MeshClient};
use wardnet_common::serve;
use wardnet_tunneller::mesh::forward::read_preamble;
use wardnet_tunneller::mesh::{InterNodeForwarder, MtlsForwarder, TenantsClient, TenantsResolver};
use wardnet_tunneller::tunnel::{ForwardRequest, TunnelRegistry};

/// Mesh leaf SPIFFE ids (URI SAN only — no DNS/IP SAN).
const TUNNELLER_SPIFFE: &str = "spiffe://wardnet.test/dev/use1/tunneller";
const TENANTS_SPIFFE: &str = "spiffe://wardnet.test/dev/global/tenants";

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

// ── Inter-node forward round-trip ──────────────────────────────────────────────

/// Stand up a forward-listener mimic: mTLS accept → read preamble → hand the stream
/// to the registry. (This is exactly what `serve_forward`'s `handle_forward` does;
/// inlined here so the test owns the registry it asserts against.)
async fn spawn_forward_listener(
    server: &Leaf,
    ca_pem: &str,
    registry: Arc<TunnelRegistry>,
) -> SocketAddr {
    let server_config = mtls::server_config_from_pem(
        server.cert_pem.as_bytes(),
        server.key_pem.as_bytes(),
        ca_pem.as_bytes(),
    )
    .expect("build forward server config");
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let registry = Arc::clone(&registry);
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await
                    && let Ok((slug, dest_port)) = read_preamble(&mut tls).await
                {
                    let req = ForwardRequest {
                        stream: Box::new(tls),
                        dest_port,
                    };
                    let _ = registry.forward(&slug, req);
                }
            });
        }
    });
    addr
}

#[tokio::test]
#[ignore = "binds a TCP listener + completes a TLS handshake"]
async fn inter_node_forward_round_trip() {
    mtls::install_crypto_provider();
    let ca = MeshCa::new();
    // Both ends are `tunneller` in the same region (node↔node).
    let server = ca.leaf(
        SanType::URI(TUNNELLER_SPIFFE.try_into().unwrap()),
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let client = ca.leaf(
        SanType::URI(TUNNELLER_SPIFFE.try_into().unwrap()),
        ExtendedKeyUsagePurpose::ClientAuth,
    );

    // The owning node: a registry with a live tunnel for "alice".
    let registry = Arc::new(TunnelRegistry::new());
    let mut registration = registry.register("alice");
    let addr = spawn_forward_listener(&server, &ca.root_pem, Arc::clone(&registry)).await;

    // The dialing node: a real MtlsForwarder, and a local client socket pair whose
    // far end stands in for the SNI-accepted tenant connection.
    let forwarder = MtlsForwarder::new(
        client.cert_pem.as_bytes(),
        client.key_pem.as_bytes(),
        ca.root_pem.as_bytes(),
        ExpectedPeer::new("tunneller", "use1"),
    )
    .expect("build forwarder");

    let pair_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pair_addr = pair_listener.local_addr().unwrap();
    let client_near = TcpStream::connect(pair_addr).await.unwrap();
    let (mut client_far, _) = pair_listener.accept().await.unwrap();

    let node_addr = format!("127.0.0.1:{}", addr.port());
    tokio::spawn(async move {
        let _ = forwarder
            .forward(&node_addr, "alice", 443, client_near)
            .await;
    });

    // The forwarded connection lands in the owning node's registry…
    let mut req = registration.rx.recv().await.expect("forwarded request");
    assert_eq!(req.dest_port, 443);

    // …and bytes written at the far client end arrive over the spliced mTLS link.
    client_far.write_all(b"hello over the mesh").await.unwrap();
    let mut buf = [0u8; 19];
    req.stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello over the mesh");
}

// ── TenantsClient resolver reads ───────────────────────────────────────────────

async fn spawn_tenants(server: &Leaf, ca_pem: &str) -> SocketAddr {
    let server_config = mtls::server_config_from_pem(
        server.cert_pem.as_bytes(),
        server.key_pem.as_bytes(),
        ca_pem.as_bytes(),
    )
    .expect("build tenants server config");
    let acceptor = TlsAcceptor::from(server_config);

    let router = Router::new()
        .route(
            "/v1/networks/{id}",
            get(|Path(id): Path<String>| async move {
                if id == "n1" {
                    Json(serde_json::json!({
                        "id": "n1",
                        "tenant_id": "t1",
                        "slug": "happy",
                        "display_name": "Happy",
                        "region": "use1",
                        "provisioning_state": "active",
                        "created_at": "2026-06-16T00:00:00Z",
                        "updated_at": "2026-06-16T00:00:00Z"
                    }))
                    .into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }),
        )
        .route(
            "/v1/tenants/{id}",
            get(|Path(id): Path<String>| async move {
                if id == "t1" {
                    Json(serde_json::json!({
                        "id": "t1",
                        "email": "t1@example.com",
                        "subscription": {
                            "id": "sub-t1",
                            "status": "active",
                            "entitlement": { "max_networks": 1, "max_daemons": 1 },
                            "stripe_customer_id": null,
                            "stripe_subscription_id": null,
                            "price_id": null,
                            "trial_expires_at": null,
                            "current_period_end": null,
                            "created_at": "2026-06-16T00:00:00Z",
                            "updated_at": "2026-06-16T00:00:00Z"
                        },
                        "created_at": "2026-06-16T00:00:00Z"
                    }))
                    .into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }),
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
async fn tenants_client_reads_network_and_tenant() {
    mtls::install_crypto_provider();
    let ca = MeshCa::new();
    let server = ca.leaf(
        SanType::URI(TENANTS_SPIFFE.try_into().unwrap()),
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let client = ca.leaf(
        SanType::URI(TUNNELLER_SPIFFE.try_into().unwrap()),
        ExtendedKeyUsagePurpose::ClientAuth,
    );

    let addr = spawn_tenants(&server, &ca.root_pem).await;

    let mesh = MeshClient::new(
        client.cert_pem.as_bytes(),
        client.key_pem.as_bytes(),
        ca.root_pem.as_bytes(),
        ExpectedPeer::new("tenants", "global"),
    )
    .expect("build mesh client");
    let tenants = TenantsClient::new(mesh, format!("https://127.0.0.1:{}", addr.port()));

    let network = tenants
        .get_network("n1")
        .await
        .expect("get_network")
        .unwrap();
    assert_eq!(network.slug, "happy");
    assert_eq!(network.tenant_id, "t1");
    assert!(tenants.get_network("missing").await.unwrap().is_none());

    let tenant = tenants.get_tenant("t1").await.expect("get_tenant").unwrap();
    assert_eq!(tenant.email, "t1@example.com");
    assert!(tenants.get_tenant("missing").await.unwrap().is_none());
}
