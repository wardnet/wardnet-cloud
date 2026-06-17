use std::sync::Arc;

use rcgen::ExtendedKeyUsagePurpose;

use super::{
    ExpectedPeer, MeshClient, ReloadableServerConfig, SpiffeId, client_verifier_from_pem,
    mesh_client, root_store_from_pem,
};
use crate::test_helpers::TestMeshCa;

/// A representative DDNS leaf id; `service`/`scope` are what acceptors/initiators pin.
const DDNS_ID: &str = "spiffe://wardnet.test/dev/use1/ddns";
const TENANTS_ID: &str = "spiffe://wardnet.test/dev/global/tenants";

fn ddns_peer() -> ExpectedPeer {
    ExpectedPeer::new("ddns", "use1")
}

#[test]
fn spiffe_id_parses_canonical_uri() {
    let id = SpiffeId::parse("spiffe://wardnet.io/prod/global/tenants").unwrap();
    assert_eq!(id.trust_domain, "wardnet.io");
    assert_eq!(id.env, "prod");
    assert_eq!(id.scope, "global");
    assert_eq!(id.service, "tenants");
}

#[test]
fn spiffe_id_rejects_non_spiffe_scheme() {
    assert!(SpiffeId::parse("https://wardnet.io/prod/global/tenants").is_err());
}

#[test]
fn spiffe_id_rejects_wrong_segment_count() {
    assert!(SpiffeId::parse("spiffe://wardnet.io/prod/global").is_err());
    assert!(SpiffeId::parse("spiffe://wardnet.io/prod/global/tenants/extra").is_err());
    assert!(SpiffeId::parse("spiffe://wardnet.io/prod//tenants").is_err());
}

#[test]
fn spiffe_id_extracted_from_leaf_uri_san() {
    let ca = TestMeshCa::new();
    let leaf = ca.leaf(DDNS_ID, ExtendedKeyUsagePurpose::ClientAuth);
    let der = rustls_pemfile::certs(&mut leaf.cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let id = SpiffeId::from_cert(&der).unwrap();
    assert_eq!(id, SpiffeId::parse(DDNS_ID).unwrap());
}

#[test]
fn root_store_parses_bundle_pem() {
    let ca = TestMeshCa::new();
    let store = root_store_from_pem(ca.root_pem().as_bytes()).unwrap();
    assert_eq!(store.len(), 1);
}

#[test]
fn root_store_rejects_empty_pem() {
    // A PEM with no CERTIFICATE blocks must be a hard error, not a silently empty store.
    assert!(root_store_from_pem(b"").is_err());
}

#[test]
fn root_store_rejects_garbage() {
    assert!(root_store_from_pem(b"not a pem").is_err());
}

#[test]
fn client_verifier_builds_from_bundle() {
    let ca = TestMeshCa::new();
    assert!(client_verifier_from_pem(ca.root_pem().as_bytes()).is_ok());
}

#[test]
fn client_verifier_rejects_garbage_bundle() {
    assert!(client_verifier_from_pem(b"not a pem").is_err());
}

#[test]
fn mesh_client_builds_with_leaf_and_bundle() {
    crate::mtls::install_crypto_provider();
    let ca = TestMeshCa::new();
    let leaf = ca.leaf(DDNS_ID, ExtendedKeyUsagePurpose::ClientAuth);
    assert!(
        mesh_client(
            leaf.cert_pem.as_bytes(),
            leaf.key_pem.as_bytes(),
            ca.root_pem().as_bytes(),
            ExpectedPeer::new("tenants", "global"),
        )
        .is_ok()
    );
}

#[test]
fn mesh_client_rejects_malformed_identity() {
    crate::mtls::install_crypto_provider();
    let ca = TestMeshCa::new();
    assert!(
        mesh_client(
            b"garbage",
            b"garbage",
            ca.root_pem().as_bytes(),
            ExpectedPeer::new("tenants", "global"),
        )
        .is_err()
    );
}

#[test]
fn mesh_client_holder_reload_swaps_client() {
    crate::mtls::install_crypto_provider();
    let ca = TestMeshCa::new();
    let leaf = ca.leaf(DDNS_ID, ExtendedKeyUsagePurpose::ClientAuth);

    let holder = MeshClient::new(
        leaf.cert_pem.as_bytes(),
        leaf.key_pem.as_bytes(),
        ca.root_pem().as_bytes(),
        ddns_peer(),
    )
    .unwrap();
    let before = holder.current();

    // Rotate to a fresh leaf and confirm the live client is a different instance —
    // the rotation actually replaced the baked-in identity.
    let rotated = ca.leaf(DDNS_ID, ExtendedKeyUsagePurpose::ClientAuth);
    holder
        .reload(
            rotated.cert_pem.as_bytes(),
            rotated.key_pem.as_bytes(),
            ca.root_pem().as_bytes(),
        )
        .unwrap();

    let after = holder.current();
    assert!(!Arc::ptr_eq(&before, &after));
}

#[test]
fn mesh_client_holder_reload_failure_keeps_previous() {
    crate::mtls::install_crypto_provider();
    let ca = TestMeshCa::new();
    let leaf = ca.leaf(DDNS_ID, ExtendedKeyUsagePurpose::ClientAuth);

    let holder = MeshClient::new(
        leaf.cert_pem.as_bytes(),
        leaf.key_pem.as_bytes(),
        ca.root_pem().as_bytes(),
        ddns_peer(),
    )
    .unwrap();
    let before = holder.current();

    assert!(holder.reload(b"garbage", b"garbage", b"garbage").is_err());

    // The previous client must still be live after a failed rotation.
    let after = holder.current();
    assert!(Arc::ptr_eq(&before, &after));
}

#[test]
fn server_config_holder_reload_swaps_config() {
    crate::mtls::install_crypto_provider();
    let ca = TestMeshCa::new();
    let leaf = ca.leaf(TENANTS_ID, ExtendedKeyUsagePurpose::ServerAuth);

    let holder = ReloadableServerConfig::new(
        leaf.cert_pem.as_bytes(),
        leaf.key_pem.as_bytes(),
        ca.root_pem().as_bytes(),
    )
    .unwrap();
    let before = holder.current();

    let rotated = ca.leaf(TENANTS_ID, ExtendedKeyUsagePurpose::ServerAuth);
    holder
        .reload(
            rotated.cert_pem.as_bytes(),
            rotated.key_pem.as_bytes(),
            ca.root_pem().as_bytes(),
        )
        .unwrap();

    let after = holder.current();
    assert!(!Arc::ptr_eq(&before, &after));
}

#[test]
fn server_config_holder_reload_failure_keeps_previous() {
    crate::mtls::install_crypto_provider();
    let ca = TestMeshCa::new();
    let leaf = ca.leaf(TENANTS_ID, ExtendedKeyUsagePurpose::ServerAuth);

    let holder = ReloadableServerConfig::new(
        leaf.cert_pem.as_bytes(),
        leaf.key_pem.as_bytes(),
        ca.root_pem().as_bytes(),
    )
    .unwrap();
    let before = holder.current();

    assert!(holder.reload(b"garbage", b"garbage", b"garbage").is_err());

    let after = holder.current();
    assert!(Arc::ptr_eq(&before, &after));
}
