//! The hot-swappable serving certificate for the bridge's own `:8443` SNI.
//!
//! A [`CertResolver`] holds the live [`rustls::ServerConfig`] behind a lock and a
//! monotonic version. The `:8443` listener clones the current config per accepted
//! bridge-SNI connection; the renewal loop swaps in a freshly issued cert (and any
//! host reloads when the DB version overtakes what it serves). At boot the
//! resolver holds a self-signed **placeholder** so the port can terminate before a
//! real certificate exists — tenant passthrough never depends on it.

use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicI64, Ordering};

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;

/// Version of the boot placeholder certificate. Real certificates start at `1`
/// (the `bridge_tls.version` default), so `served_version() > PLACEHOLDER_VERSION`
/// means a real cert is live.
pub const PLACEHOLDER_VERSION: i64 = 0;

/// Holds the live serving [`ServerConfig`] and the version of the certificate it
/// was built from.
///
/// When `client_verifier` is `Some`, every rebuilt [`ServerConfig`] (placeholder,
/// installs, rotations) requires a mesh-chained client certificate — this is how
/// service-mesh mTLS is switched on for the listener. `None` preserves the legacy
/// `.with_no_client_auth()` behaviour (daemon-/public-facing listeners that are
/// authenticated at the application layer instead).
pub struct CertResolver {
    config: RwLock<Arc<ServerConfig>>,
    version: AtomicI64,
    client_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

impl CertResolver {
    /// Build a resolver seeded with a self-signed placeholder certificate and **no**
    /// client-auth (application-layer-authenticated listener).
    ///
    /// # Errors
    /// Returns an error if the placeholder cert or rustls config cannot be built.
    pub fn with_placeholder() -> anyhow::Result<Arc<Self>> {
        Self::seed(None)
    }

    /// Build a resolver seeded with a placeholder certificate that **requires a
    /// mesh-chained client certificate** (service-mesh mTLS).
    ///
    /// Build `verifier` with [`crate::mtls::client_verifier_from_pem`].
    ///
    /// # Errors
    /// Returns an error if the placeholder cert or rustls config cannot be built.
    pub fn with_placeholder_mtls(
        verifier: Arc<dyn ClientCertVerifier>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::seed(Some(verifier))
    }

    /// Seed a resolver with the placeholder cert, applying the optional client
    /// verifier to every config it will build.
    fn seed(client_verifier: Option<Arc<dyn ClientCertVerifier>>) -> anyhow::Result<Arc<Self>> {
        let config = placeholder_config(client_verifier.clone())?;
        Ok(Arc::new(Self {
            config: RwLock::new(config),
            version: AtomicI64::new(PLACEHOLDER_VERSION),
            client_verifier,
        }))
    }

    /// The current serving config (cheap `Arc` clone) for a `TlsAcceptor`.
    #[must_use]
    pub fn current(&self) -> Arc<ServerConfig> {
        self.config.read().expect("cert lock poisoned").clone()
    }

    /// The version of the certificate currently being served.
    #[must_use]
    pub fn served_version(&self) -> i64 {
        self.version.load(Ordering::Acquire)
    }

    /// Whether a real (non-placeholder) certificate is live.
    #[must_use]
    pub fn is_provisioned(&self) -> bool {
        self.served_version() > PLACEHOLDER_VERSION
    }

    /// Hot-swap to the certificate built from `chain_pem` + `key_pem`, recording
    /// `version`. New connections pick it up immediately.
    ///
    /// # Errors
    /// Returns an error if the PEM cannot be parsed into a rustls config.
    pub fn install(&self, chain_pem: &[u8], key_pem: &[u8], version: i64) -> anyhow::Result<()> {
        let config = server_config_from_pem(chain_pem, key_pem, self.client_verifier.clone())?;
        *self.config.write().expect("cert lock poisoned") = config;
        self.version.store(version, Ordering::Release);
        Ok(())
    }
}

/// Build a rustls [`ServerConfig`] (ALPN: h2 + http/1.1) from a PEM chain + key.
///
/// When `client_verifier` is `Some`, the listener requires a client certificate
/// the verifier accepts (mesh mTLS); when `None`, client auth is disabled and the
/// request is authenticated at the application layer.
fn server_config_from_pem(
    chain_pem: &[u8],
    key_pem: &[u8],
    client_verifier: Option<Arc<dyn ClientCertVerifier>>,
) -> anyhow::Result<Arc<ServerConfig>> {
    let mut chain_reader = chain_pem;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut chain_reader)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse certificate chain PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("certificate chain PEM contained no certificates");
    }

    let mut key_reader = key_pem;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| anyhow::anyhow!("failed to parse leaf key PEM: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("leaf key PEM contained no private key"))?;

    let builder = ServerConfig::builder();
    let with_certs = match client_verifier {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    };
    let mut config = with_certs
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("failed to build rustls server config: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Generate a throwaway self-signed placeholder certificate for `bridge.invalid`,
/// applying the optional mesh client verifier.
fn placeholder_config(
    client_verifier: Option<Arc<dyn ClientCertVerifier>>,
) -> anyhow::Result<Arc<ServerConfig>> {
    let key_pair = rcgen::KeyPair::generate()?;
    let params = rcgen::CertificateParams::new(vec!["bridge.invalid".to_owned()])?;
    let cert = params.self_signed(&key_pair)?;
    server_config_from_pem(
        cert.pem().as_bytes(),
        key_pair.serialize_pem().as_bytes(),
        client_verifier,
    )
}

#[cfg(test)]
mod tests;
