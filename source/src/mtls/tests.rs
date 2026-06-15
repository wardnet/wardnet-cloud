use std::sync::Arc;

use rcgen::ExtendedKeyUsagePurpose;

use super::{MeshClient, client_verifier_from_pem, mesh_client, root_store_from_pem};
use crate::test_helpers::TestMeshCa;

#[test]
fn root_store_parses_ca_pem() {
    let ca = TestMeshCa::new();
    let store = root_store_from_pem(ca.root_pem().as_bytes()).unwrap();
    assert_eq!(store.len(), 1);
}

#[test]
fn root_store_rejects_empty_pem() {
    // A PEM with no CERTIFICATE blocks must be a hard error, not a silently empty
    // (trust-nothing-or-everything) store.
    assert!(root_store_from_pem(b"").is_err());
    assert!(
        root_store_from_pem(b"-----BEGIN PRIVATE KEY-----\nMA==\n-----END PRIVATE KEY-----\n")
            .is_err()
    );
}

#[test]
fn root_store_rejects_garbage() {
    assert!(root_store_from_pem(b"not a pem at all").is_err());
}

#[test]
fn client_verifier_builds_from_root() {
    crate::tls::install_crypto_provider();
    let ca = TestMeshCa::new();
    assert!(client_verifier_from_pem(ca.root_pem().as_bytes()).is_ok());
}

#[test]
fn client_verifier_rejects_garbage_root() {
    crate::tls::install_crypto_provider();
    assert!(client_verifier_from_pem(b"not pem").is_err());
}

#[test]
fn mesh_client_builds_with_leaf_and_root() {
    crate::tls::install_crypto_provider();
    let ca = TestMeshCa::new();
    let leaf = ca.leaf("ddns.use1.mesh", ExtendedKeyUsagePurpose::ClientAuth);
    assert!(
        mesh_client(
            leaf.cert_pem.as_bytes(),
            leaf.key_pem.as_bytes(),
            ca.root_pem().as_bytes(),
        )
        .is_ok()
    );
}

#[test]
fn mesh_client_rejects_malformed_identity() {
    crate::tls::install_crypto_provider();
    let ca = TestMeshCa::new();
    // A cert with no matching key is not a usable identity.
    assert!(
        mesh_client(
            ca.root_pem().as_bytes(),
            b"-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----\n",
            ca.root_pem().as_bytes(),
        )
        .is_err()
    );
}

#[test]
fn mesh_client_holder_reload_swaps_client() {
    crate::tls::install_crypto_provider();
    let ca = TestMeshCa::new();
    let leaf = ca.leaf("ddns.use1.mesh", ExtendedKeyUsagePurpose::ClientAuth);

    let holder = MeshClient::new(
        leaf.cert_pem.as_bytes(),
        leaf.key_pem.as_bytes(),
        ca.root_pem().as_bytes(),
    )
    .unwrap();

    let before = holder.current();

    // Rotate to a fresh leaf and confirm the live client is a different instance —
    // the rotation actually replaced the baked-in identity.
    let rotated = ca.leaf("ddns.use1.mesh", ExtendedKeyUsagePurpose::ClientAuth);
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
    crate::tls::install_crypto_provider();
    let ca = TestMeshCa::new();
    let leaf = ca.leaf("ddns.use1.mesh", ExtendedKeyUsagePurpose::ClientAuth);

    let holder = MeshClient::new(
        leaf.cert_pem.as_bytes(),
        leaf.key_pem.as_bytes(),
        ca.root_pem().as_bytes(),
    )
    .unwrap();
    let before = holder.current();

    assert!(holder.reload(b"garbage", b"garbage", b"garbage").is_err());

    // The previous client must still be live after a failed rotation.
    let after = holder.current();
    assert!(Arc::ptr_eq(&before, &after));
}
