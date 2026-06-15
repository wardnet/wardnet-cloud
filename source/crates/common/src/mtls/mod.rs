//! Service-mesh mTLS primitives shared by the cloud services.
//!
//! **Status (#610):** these are verified primitives, not yet wired into a running
//! listener or client. No service serves an mTLS listener or makes an outbound
//! mesh call yet; both are turned on at the three-binary split (WS-E). Until then
//! these are exercised only by tests.
//!
//! The split into Tenants / DDNS / Tunneller turns what used to be in-process
//! calls into network hops. Those hops are authenticated with **mutual TLS over a
//! private two-root PKI** (see `docs/adr-service-decomposition.md`): a cold mesh
//! root signs per-region intermediates which mint per-service leaves at deploy
//! time. Each service holds only `leaf cert + leaf key + mesh-root cert` — there
//! is no online mesh CA.
//!
//! This module is the concrete surface both sides use:
//! - **server**: [`client_verifier_from_pem`] builds a [`ClientCertVerifier`] from
//!   the mesh-root PEM; a service's internal listener installs it to require a
//!   mesh-chained client cert instead of `.with_no_client_auth()`.
//! - **client**: [`MeshClient`] holds a `reqwest::Client` that presents this
//!   service's leaf and trusts *only* the mesh root. A `reqwest::Client` bakes its
//!   identity at build time, so rotation rebuilds the client — [`MeshClient`] keeps
//!   it behind an [`ArcSwap`] so the swap is lock-free and in-flight callers are
//!   unaffected.
//!
//! Revocation is by **short certificate TTL**, not CRL/OCSP — a rotated-out leaf
//! simply stops being reissued (consistent with the serving-cert renewal model).

use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;

/// Install the aws-lc-rs [`CryptoProvider`](rustls::crypto::CryptoProvider) as the
/// process default (idempotent).
///
/// rustls 0.23 requires a default crypto provider before any TLS work; a service
/// that serves a mesh-mTLS listener or builds a [`ClientCertVerifier`] calls this
/// once at startup. Idempotent — a second call is a no-op.
pub fn install_crypto_provider() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
}

/// Parse one or more PEM CA certificates into a [`RootCertStore`] of trust anchors.
///
/// Used for both the mesh root (peer-service authZ) and, later, the daemon root
/// (install authZ) — never mix the two stores, so the roots can't be path-confused.
///
/// # Errors
/// Returns an error if the PEM contains no certificates or any certificate is
/// malformed.
pub fn root_store_from_pem(pem: &[u8]) -> anyhow::Result<RootCertStore> {
    let mut reader = pem;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse root CA PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("root CA PEM contained no certificates");
    }

    let mut store = RootCertStore::empty();
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| anyhow::anyhow!("invalid root CA certificate: {e}"))?;
    }
    Ok(store)
}

/// Build a [`ClientCertVerifier`] that accepts only leaves chained to
/// `mesh_root_pem`.
///
/// Install the returned verifier on a service's internal mTLS listener to turn on
/// client-auth instead of `.with_no_client_auth()`. A handshake presenting no
/// client certificate, or one rooted in a different CA, is rejected at the TLS
/// layer before any request handler runs.
///
/// # Errors
/// Returns an error if `mesh_root_pem` cannot be parsed or the verifier cannot be
/// built (e.g. the root store is empty).
pub fn client_verifier_from_pem(
    mesh_root_pem: &[u8],
) -> anyhow::Result<Arc<dyn ClientCertVerifier>> {
    let roots = root_store_from_pem(mesh_root_pem)?;
    WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build mTLS client verifier: {e}"))
}

/// Build a rustls [`ServerConfig`] for an internal mesh listener: it presents the
/// `server_cert_pem` chain + `server_key_pem`, and **requires** a client
/// certificate chained to `mesh_root_pem`. A handshake presenting no client cert,
/// or one from a different CA, is rejected — so mTLS *is* the authentication for
/// the endpoints served behind it (e.g. Tenants' `/v1/introspect`).
///
/// # Errors
/// Returns an error if any PEM is malformed/empty or the config cannot be built.
pub fn server_config_from_pem(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    mesh_root_pem: &[u8],
) -> anyhow::Result<Arc<ServerConfig>> {
    let verifier = client_verifier_from_pem(mesh_root_pem)?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &server_cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse mesh server certificate PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("mesh server certificate PEM contained no certificates");
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &server_key_pem[..])
        .map_err(|e| anyhow::anyhow!("failed to parse mesh server key PEM: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("mesh server key PEM contained no private key"))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("failed to build mesh server config: {e}"))?;

    Ok(Arc::new(config))
}

/// Build a `reqwest::Client` that presents `leaf` as its client identity and
/// trusts **only** `mesh_root_pem` (built-in/native roots are disabled).
///
/// This is the outbound half of mesh mTLS — e.g. the DDNS reconcile reaper calling
/// the Tenants introspection endpoint. The leaf cert + key are combined into a
/// single PEM bundle for `reqwest::Identity::from_pem`, which accepts the
/// certificate and PKCS#8 key sections in any order.
///
/// # Errors
/// Returns an error if the identity or root PEM is malformed, or the client cannot
/// be built.
pub fn mesh_client(
    leaf_cert_pem: &[u8],
    leaf_key_pem: &[u8],
    mesh_root_pem: &[u8],
) -> anyhow::Result<reqwest::Client> {
    // reqwest's rustls `Identity::from_pem` scans the bundle for the private key and
    // the certificate chain, so the section order does not matter; we concatenate
    // key then chain with a separating newline for safety.
    let mut bundle = Vec::with_capacity(leaf_key_pem.len() + leaf_cert_pem.len() + 1);
    bundle.extend_from_slice(leaf_key_pem);
    bundle.push(b'\n');
    bundle.extend_from_slice(leaf_cert_pem);

    let identity = reqwest::Identity::from_pem(&bundle)
        .map_err(|e| anyhow::anyhow!("failed to build mTLS client identity: {e}"))?;
    let root = reqwest::Certificate::from_pem(mesh_root_pem)
        .map_err(|e| anyhow::anyhow!("failed to parse mesh root for client: {e}"))?;

    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(root)
        .identity(identity)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build mTLS reqwest client: {e}"))
}

/// A hot-swappable mesh mTLS HTTP client.
///
/// `reqwest::Client` bakes its TLS identity at build time, so rotating the leaf
/// certificate means building a fresh client. [`MeshClient`] keeps the live client
/// behind an [`ArcSwap`]: callers take a cheap snapshot via [`MeshClient::current`]
/// and keep using it for the life of their request, while [`MeshClient::reload`]
/// swaps in a rebuilt client lock-free on the next cert rotation.
pub struct MeshClient {
    client: ArcSwap<reqwest::Client>,
}

impl MeshClient {
    /// Build a `MeshClient` from this service's leaf and the mesh root.
    ///
    /// # Errors
    /// Returns an error if the underlying [`mesh_client`] cannot be built.
    pub fn new(
        leaf_cert_pem: &[u8],
        leaf_key_pem: &[u8],
        mesh_root_pem: &[u8],
    ) -> anyhow::Result<Arc<Self>> {
        let client = mesh_client(leaf_cert_pem, leaf_key_pem, mesh_root_pem)?;
        Ok(Arc::new(Self {
            client: ArcSwap::from_pointee(client),
        }))
    }

    /// A snapshot of the current client. Cheap (`Arc` clone); safe to hold across
    /// a request even if [`reload`](Self::reload) swaps the client meanwhile.
    #[must_use]
    pub fn current(&self) -> Arc<reqwest::Client> {
        self.client.load_full()
    }

    /// Rebuild the client from a freshly rotated leaf and swap it in atomically.
    ///
    /// # Errors
    /// Returns an error if the new client cannot be built; the previous client is
    /// left in place on failure.
    pub fn reload(
        &self,
        leaf_cert_pem: &[u8],
        leaf_key_pem: &[u8],
        mesh_root_pem: &[u8],
    ) -> anyhow::Result<()> {
        let client = mesh_client(leaf_cert_pem, leaf_key_pem, mesh_root_pem)?;
        self.client.store(Arc::new(client));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
