use super::{CertResolver, PLACEHOLDER_VERSION};

fn self_signed_pem(fqdn: &str) -> (String, String) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![fqdn.to_owned()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

#[test]
fn placeholder_is_not_provisioned() {
    crate::tls::install_crypto_provider();
    let resolver = CertResolver::with_placeholder().unwrap();
    assert_eq!(resolver.served_version(), PLACEHOLDER_VERSION);
    assert!(!resolver.is_provisioned());
    // a usable config is available even pre-provisioning
    let _ = resolver.current();
}

#[test]
fn install_swaps_and_marks_provisioned() {
    crate::tls::install_crypto_provider();
    let resolver = CertResolver::with_placeholder().unwrap();
    let (chain, key) = self_signed_pem("bridge.svc.prod.use1.wardnet.network");

    resolver
        .install(chain.as_bytes(), key.as_bytes(), 1)
        .unwrap();

    assert_eq!(resolver.served_version(), 1);
    assert!(resolver.is_provisioned());
}

#[test]
fn install_rejects_garbage_pem() {
    crate::tls::install_crypto_provider();
    let resolver = CertResolver::with_placeholder().unwrap();
    assert!(resolver.install(b"not pem", b"not pem", 1).is_err());
    // remains on the placeholder
    assert!(!resolver.is_provisioned());
}

// ── Service-mesh mTLS handshake ────────────────────────────────────────────────
//
// These drive a real rustls handshake over an in-memory duplex pipe to prove the
// client-auth wiring in `server_config_from_pem`: a mesh-chained client leaf is
// accepted, while a client with no certificate or one rooted in a *different* mesh
// CA is rejected at the TLS layer (before any request handler runs).

use std::sync::Arc;

use rcgen::ExtendedKeyUsagePurpose;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::test_helpers::{TestLeaf, TestMeshCa};

const SERVER_FQDN: &str = "tenants.svc.use1.mesh";

/// A client `ClientConfig` trusting `root_pem` and optionally presenting `leaf`.
fn client_config(root_pem: &str, leaf: Option<&TestLeaf>) -> rustls::ClientConfig {
    let roots = crate::mtls::root_store_from_pem(root_pem.as_bytes()).unwrap();
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    match leaf {
        Some(leaf) => {
            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut leaf.cert_pem.as_bytes())
                    .collect::<Result<_, _>>()
                    .unwrap();
            let key: PrivateKeyDer<'static> =
                rustls_pemfile::private_key(&mut leaf.key_pem.as_bytes())
                    .unwrap()
                    .unwrap();
            builder.with_client_auth_cert(certs, key).unwrap()
        }
        None => builder.with_no_client_auth(),
    }
}

/// Drive a full handshake between a mesh-mTLS server and `client_cfg`; returns
/// whether the **server** accepted the connection.
async fn server_accepts(server_ca: &TestMeshCa, client_cfg: rustls::ClientConfig) -> bool {
    let server_leaf = server_ca.leaf(SERVER_FQDN, ExtendedKeyUsagePurpose::ServerAuth);
    let verifier = crate::mtls::client_verifier_from_pem(server_ca.root_pem().as_bytes()).unwrap();
    let server_cfg = super::server_config_from_pem(
        server_leaf.cert_pem.as_bytes(),
        server_leaf.key_pem.as_bytes(),
        Some(verifier),
    )
    .unwrap();

    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let name = ServerName::try_from(SERVER_FQDN).unwrap();

    // Drive both halves concurrently and keep the client stream alive until the
    // server's handshake fully completes (rustls writes post-handshake messages to
    // the client). The client result is ignored — the server verdict is what the
    // tests assert on (a rejected client cert fails the accept).
    let (server_res, _client_res) = tokio::join!(
        acceptor.accept(server_io),
        connector.connect(name, client_io)
    );
    server_res.is_ok()
}

#[tokio::test]
async fn mtls_handshake_accepts_mesh_chained_client() {
    crate::tls::install_crypto_provider();
    let ca = TestMeshCa::new();
    let client_leaf = ca.leaf("ddns.use1.mesh", ExtendedKeyUsagePurpose::ClientAuth);
    let cfg = client_config(ca.root_pem(), Some(&client_leaf));
    assert!(server_accepts(&ca, cfg).await);
}

#[tokio::test]
async fn mtls_handshake_rejects_client_without_cert() {
    crate::tls::install_crypto_provider();
    let ca = TestMeshCa::new();
    let cfg = client_config(ca.root_pem(), None);
    assert!(!server_accepts(&ca, cfg).await);
}

#[tokio::test]
async fn mtls_handshake_rejects_wrong_root_client() {
    crate::tls::install_crypto_provider();
    let server_ca = TestMeshCa::new();
    // Client leaf is minted by an unrelated CA — the server must reject it even
    // though the client itself trusts the server's root.
    let other_ca = TestMeshCa::new();
    let foreign_leaf = other_ca.leaf("rogue.mesh", ExtendedKeyUsagePurpose::ClientAuth);
    let cfg = client_config(server_ca.root_pem(), Some(&foreign_leaf));
    assert!(!server_accepts(&server_ca, cfg).await);
}
