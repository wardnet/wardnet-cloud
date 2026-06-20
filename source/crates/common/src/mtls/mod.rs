//! Service-mesh mTLS primitives shared by every cloud service.
//!
//! The mesh (Tenants ↔ DDNS ↔ Tunneller node↔node) authenticates peers with
//! **SPIFFE-identified** mutual TLS. The deployer (inforge) mints each service a leaf
//! whose only SAN is a SPIFFE URI — `spiffe://<trust_domain>/<env>/<scope>/<service>`,
//! **no DNS SAN** — and delivers a per-scope **trust bundle of intermediates** (not a
//! single root). On renewal it re-projects the leaf/key/bundle files **in place**, so a
//! service watches those files ([`watch_mesh_files`]) and hot-reloads its TLS material
//! without restarting.
//!
//! Authorization is split between the two ends of a call:
//!
//! - **Initiators** pin their target's identity ([`ExpectedPeer`]) inside a custom
//!   [`ServerCertVerifier`] (built by [`client_config_from_pem`] / [`mesh_client`]):
//!   it chain-validates the server leaf against the bundle anchors, **ignores the DNS
//!   SNI** (there is none), and asserts the peer leaf's `service` + `scope`. This is the
//!   replacement for the lost DNS-name check.
//! - **Acceptors** keep an ordinary [`server_config_from_pem`] (rustls enforces the
//!   client-cert chain), then read the post-handshake peer leaf, parse its [`SpiffeId`]
//!   ([`peer_spiffe_id`]), and apply the scope-direction rule in their own accept loop —
//!   so adding a new in-bundle caller needs no code change in the acceptor.
//!
//! Rotation without restart is provided by [`MeshClient`] (reqwest client) and
//! [`ReloadableServerConfig`] (acceptor config), each an [`ArcSwap`] snapshot a
//! connection reads once; [`watch_mesh_files`] re-reads the three files on change and
//! drives every consumer's `reload`.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ParsedCertificate, WebPkiClientVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};

/// Install the process-default rustls crypto provider (aws-lc-rs).
///
/// rustls 0.23 requires a process-default [`CryptoProvider`](rustls::crypto::CryptoProvider)
/// before any TLS config is built. Idempotent — a second call is a no-op.
pub fn install_crypto_provider() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
}

/// Parse one or more PEM certificates into a [`RootCertStore`] of trust anchors.
///
/// Used for the mesh **trust bundle** — a per-scope set of intermediates (every cert in
/// the PEM becomes an anchor), not a single root.
///
/// # Errors
/// Returns an error if the PEM contains no certificates or any certificate is malformed.
pub fn root_store_from_pem(pem: &[u8]) -> anyhow::Result<RootCertStore> {
    let mut reader = pem;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse trust bundle PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("trust bundle PEM contained no certificates");
    }

    let mut store = RootCertStore::empty();
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| anyhow::anyhow!("invalid trust bundle certificate: {e}"))?;
    }
    Ok(store)
}

/// Build a [`ClientCertVerifier`] that accepts only client leaves chained to the mesh
/// **trust bundle**. Install it on an acceptor to require a mesh-chained client cert
/// instead of `.with_no_client_auth()`.
///
/// # Errors
/// Returns an error if `trust_bundle_pem` cannot be parsed or the verifier cannot be
/// built (e.g. the bundle is empty).
pub fn client_verifier_from_pem(
    trust_bundle_pem: &[u8],
) -> anyhow::Result<Arc<dyn ClientCertVerifier>> {
    let roots = root_store_from_pem(trust_bundle_pem)?;
    WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build mTLS client verifier: {e}"))
}

/// Build a [`ServerConfig`] for a mesh listener: presents `server_cert_pem` /
/// `server_key_pem` and **requires** a client certificate chained to
/// `trust_bundle_pem`. A handshake presenting no client cert, or one from a different
/// CA, is rejected — the mutual-TLS handshake *is* the SERVICE authentication. The
/// acceptor still parses the peer [`SpiffeId`] afterwards to apply the scope rule.
///
/// # Errors
/// Returns an error if any PEM is malformed/empty or the config cannot be built.
pub fn server_config_from_pem(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    trust_bundle_pem: &[u8],
) -> anyhow::Result<Arc<ServerConfig>> {
    let verifier = client_verifier_from_pem(trust_bundle_pem)?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &server_cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse server certificate PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("mesh server certificate PEM contained no certificates");
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &server_key_pem[..])
        .map_err(|e| anyhow::anyhow!("failed to parse server key PEM: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("server key PEM contained no private key"))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("failed to build mesh server config: {e}"))?;
    Ok(Arc::new(config))
}

// ── SPIFFE identity ───────────────────────────────────────────────────────────────

/// A parsed SPIFFE identity: `spiffe://<trust_domain>/<env>/<scope>/<service>`.
///
/// `scope` is `global` or a region slug; `service` is the canonical mesh name
/// (`tenants`, `ddns`, `tunneller`). A service learns its **own** identity by parsing
/// its own leaf at boot, and compares **peers** against this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    /// The trust domain (the authority that issued the id), e.g. `wardnet.io`.
    pub trust_domain: String,
    /// The deployment environment, e.g. `prod` / `staging` / `dev`.
    pub env: String,
    /// `global` for a global-scope service, otherwise the region slug.
    pub scope: String,
    /// The canonical mesh service name (`tenants` / `ddns` / `tunneller`).
    pub service: String,
}

impl SpiffeId {
    /// Parse a SPIFFE URI of the exact form
    /// `spiffe://<trust_domain>/<env>/<scope>/<service>`.
    ///
    /// # Errors
    /// Returns an error if the URI is not `spiffe://` or does not have exactly the four
    /// non-empty path segments.
    pub fn parse(uri: &str) -> anyhow::Result<Self> {
        let rest = uri
            .strip_prefix("spiffe://")
            .ok_or_else(|| anyhow::anyhow!("not a spiffe:// URI: {uri}"))?;
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() != 4 || parts.iter().any(|s| s.is_empty()) {
            anyhow::bail!(
                "spiffe URI must be spiffe://<trust_domain>/<env>/<scope>/<service>: {uri}"
            );
        }
        Ok(Self {
            trust_domain: parts[0].to_owned(),
            env: parts[1].to_owned(),
            scope: parts[2].to_owned(),
            service: parts[3].to_owned(),
        })
    }

    /// Extract the SPIFFE id from a certificate's first URI SAN.
    ///
    /// # Errors
    /// Returns an error if the DER cannot be parsed, the cert has no URI SAN, or the URI
    /// is not a well-formed SPIFFE id.
    pub fn from_cert(der: &CertificateDer<'_>) -> anyhow::Result<Self> {
        use x509_parser::extensions::GeneralName;
        use x509_parser::prelude::FromDer;

        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.as_ref())
            .map_err(|e| anyhow::anyhow!("failed to parse peer certificate: {e}"))?;
        let san = cert
            .subject_alternative_name()
            .map_err(|e| anyhow::anyhow!("failed to parse peer SAN: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("peer certificate has no SAN extension"))?;
        for name in &san.value.general_names {
            if let GeneralName::URI(uri) = name {
                return Self::parse(uri);
            }
        }
        anyhow::bail!("peer certificate has no URI SAN")
    }
}

/// Extract the [`SpiffeId`] from a TLS peer's leaf (first) certificate.
///
/// # Errors
/// Returns an error if the peer presented no certificates or the leaf has no valid
/// SPIFFE URI SAN.
pub fn peer_spiffe_id(peer_certs: &[CertificateDer<'_>]) -> anyhow::Result<SpiffeId> {
    let leaf = peer_certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("peer presented no certificates"))?;
    SpiffeId::from_cert(leaf)
}

/// Parse this service's **own** [`SpiffeId`] from its leaf certificate PEM (the first
/// certificate). A service learns its own scope/service at boot from this, instead of
/// configuring its own name.
///
/// # Errors
/// Returns an error if the PEM has no certificate or the leaf has no valid SPIFFE URI
/// SAN.
pub fn own_spiffe_id(leaf_cert_pem: &[u8]) -> anyhow::Result<SpiffeId> {
    let cert = rustls_pemfile::certs(&mut &leaf_cert_pem[..])
        .next()
        .ok_or_else(|| anyhow::anyhow!("leaf certificate PEM contained no certificates"))?
        .map_err(|e| anyhow::anyhow!("failed to parse leaf certificate PEM: {e}"))?;
    SpiffeId::from_cert(&cert)
}

/// The identity an initiator expects of its mesh target: a specific `service` + `scope`.
///
/// Pinned on the dialer (intrinsic to the call) and asserted by [`SpiffeServerVerifier`].
#[derive(Debug, Clone)]
pub struct ExpectedPeer {
    /// The canonical mesh service name the target must present (`tenants`, …).
    pub service: String,
    /// The scope the target must present (`global` or a region slug).
    pub scope: String,
}

impl ExpectedPeer {
    /// Construct an [`ExpectedPeer`] from a `service` and `scope`.
    pub fn new(service: impl Into<String>, scope: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            scope: scope.into(),
        }
    }
}

// ── client side: SPIFFE-pinning server-cert verifier ────────────────────────────────

/// A rustls [`ServerCertVerifier`] that chain-validates the server leaf against the mesh
/// **trust bundle** and then asserts the peer leaf's SPIFFE `service` + `scope` match an
/// [`ExpectedPeer`] — **ignoring the DNS SNI** entirely (mesh leaves carry no DNS SAN).
#[derive(Debug)]
struct SpiffeServerVerifier {
    roots: Arc<RootCertStore>,
    supported_algs: WebPkiSupportedAlgorithms,
    expected: ExpectedPeer,
}

impl ServerCertVerifier for SpiffeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.supported_algs.all,
        )?;

        let id = SpiffeId::from_cert(end_entity)
            .map_err(|e| rustls::Error::General(format!("peer SPIFFE id: {e}")))?;
        if id.service != self.expected.service || id.scope != self.expected.scope {
            return Err(rustls::Error::General(format!(
                "mesh peer identity mismatch: expected service={}/scope={}, got service={}/scope={}",
                self.expected.service, self.expected.scope, id.service, id.scope,
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Build a rustls [`ClientConfig`] that presents `leaf` as the client identity and
/// verifies the server with a [`SpiffeServerVerifier`] pinned to `expected` — chain
/// against `trust_bundle_pem`, ignore the DNS SNI, assert the peer SPIFFE id.
///
/// Shared by [`mesh_client`] (reqwest, via `use_preconfigured_tls`) and the Tunneller
/// inter-node forwarder (a raw `tokio-rustls` connector).
///
/// # Errors
/// Returns an error if any PEM is malformed/empty, no crypto provider is installed, or
/// the config cannot be built.
pub fn client_config_from_pem(
    leaf_cert_pem: &[u8],
    leaf_key_pem: &[u8],
    trust_bundle_pem: &[u8],
    expected: ExpectedPeer,
) -> anyhow::Result<ClientConfig> {
    let roots = Arc::new(root_store_from_pem(trust_bundle_pem)?);
    let provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| anyhow::anyhow!("no default rustls crypto provider installed"))?;
    let verifier = Arc::new(SpiffeServerVerifier {
        roots,
        supported_algs: provider.signature_verification_algorithms,
        expected,
    });

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &leaf_cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse mesh leaf certificate PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("mesh leaf certificate PEM contained no certificates");
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &leaf_key_pem[..])
        .map_err(|e| anyhow::anyhow!("failed to parse mesh leaf key PEM: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("mesh leaf key PEM contained no private key"))?;

    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("failed to build mesh client config: {e}"))
}

/// Build a `reqwest::Client` that presents `leaf` as its client identity and verifies
/// the mesh peer with a [`SpiffeServerVerifier`] pinned to `expected`.
///
/// # Errors
/// Returns an error if the identity/bundle PEM is malformed or the client cannot be
/// built.
pub fn mesh_client(
    leaf_cert_pem: &[u8],
    leaf_key_pem: &[u8],
    trust_bundle_pem: &[u8],
    expected: ExpectedPeer,
) -> anyhow::Result<reqwest::Client> {
    let config = client_config_from_pem(leaf_cert_pem, leaf_key_pem, trust_bundle_pem, expected)?;
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build mTLS reqwest client: {e}"))
}

/// A hot-swappable mesh mTLS HTTP client.
///
/// A `reqwest::Client` bakes its TLS identity at build time, so rotating the leaf means
/// building a fresh client. [`MeshClient`] keeps the live client in an [`ArcSwap`]:
/// callers take a cheap snapshot ([`MeshClient::current`]) and a file-watcher swaps in a
/// new client ([`MeshClient::reload`]) on rotation. The pinned [`ExpectedPeer`] is held
/// once and reused across reloads.
pub struct MeshClient {
    client: ArcSwap<reqwest::Client>,
    expected: ExpectedPeer,
}

impl MeshClient {
    /// Build a [`MeshClient`] pinned to `expected`.
    ///
    /// # Errors
    /// Returns an error if the initial client cannot be built (see [`mesh_client`]).
    pub fn new(
        leaf_cert_pem: &[u8],
        leaf_key_pem: &[u8],
        trust_bundle_pem: &[u8],
        expected: ExpectedPeer,
    ) -> anyhow::Result<Arc<Self>> {
        let client = mesh_client(
            leaf_cert_pem,
            leaf_key_pem,
            trust_bundle_pem,
            expected.clone(),
        )?;
        Ok(Arc::new(Self {
            client: ArcSwap::from_pointee(client),
            expected,
        }))
    }

    /// A snapshot of the current client. Cheap (`Arc` clone); safe to hold across a
    /// request even if [`reload`](Self::reload) swaps the client meanwhile.
    #[must_use]
    pub fn current(&self) -> Arc<reqwest::Client> {
        self.client.load_full()
    }

    /// Rebuild the client from freshly rotated material and swap it in atomically. The
    /// pinned [`ExpectedPeer`] is preserved.
    ///
    /// # Errors
    /// Returns an error if the new client cannot be built; the previous client is left
    /// in place on failure.
    pub fn reload(
        &self,
        leaf_cert_pem: &[u8],
        leaf_key_pem: &[u8],
        trust_bundle_pem: &[u8],
    ) -> anyhow::Result<()> {
        let client = mesh_client(
            leaf_cert_pem,
            leaf_key_pem,
            trust_bundle_pem,
            self.expected.clone(),
        )?;
        self.client.store(Arc::new(client));
        Ok(())
    }
}

/// A hot-swappable mesh mTLS [`ServerConfig`] for an acceptor.
///
/// The acceptor reads [`current`](Self::current) once per accepted connection and builds
/// a `TlsAcceptor` from it; a file-watcher swaps in a fresh config ([`reload`](Self::reload))
/// on leaf rotation. In-flight connections keep the config they started with.
pub struct ReloadableServerConfig {
    config: ArcSwap<ServerConfig>,
}

impl ReloadableServerConfig {
    /// Build a holder from the initial mesh server material.
    ///
    /// # Errors
    /// Returns an error if the config cannot be built (see [`server_config_from_pem`]).
    pub fn new(
        server_cert_pem: &[u8],
        server_key_pem: &[u8],
        trust_bundle_pem: &[u8],
    ) -> anyhow::Result<Arc<Self>> {
        let config = server_config_from_pem(server_cert_pem, server_key_pem, trust_bundle_pem)?;
        Ok(Arc::new(Self {
            config: ArcSwap::new(config),
        }))
    }

    /// A snapshot of the current server config. Cheap (`Arc` clone).
    #[must_use]
    pub fn current(&self) -> Arc<ServerConfig> {
        self.config.load_full()
    }

    /// Rebuild the server config from rotated material and swap it in atomically.
    ///
    /// # Errors
    /// Returns an error if the new config cannot be built; the previous config is left
    /// in place on failure.
    pub fn reload(
        &self,
        server_cert_pem: &[u8],
        server_key_pem: &[u8],
        trust_bundle_pem: &[u8],
    ) -> anyhow::Result<()> {
        let config = server_config_from_pem(server_cert_pem, server_key_pem, trust_bundle_pem)?;
        self.config.store(config);
        Ok(())
    }
}

/// Watch the directories holding the mesh PEM files and invoke `on_change` after each
/// change, debounced and **deduplicated on file contents**.
///
/// inforge re-projects `leaf.crt` / `leaf.key` / `bundle.crt` **in place** on renewal;
/// this watches their parent directories (more robust than watching the files, since an
/// atomic replace swaps the inode) and calls `on_change` — which should re-read the three
/// files and `reload` every consumer ([`MeshClient`], [`ReloadableServerConfig`]). The
/// watcher runs on a dedicated thread that lives for the process; this returns once it is
/// armed.
///
/// `on_change` fires only when the combined contents of `paths` actually differ from what
/// was last seen, so a directory that emits a continuous stream of spurious change events
/// (some networked/overlay filesystems do) does not trigger a reload storm.
///
/// # Errors
/// Returns an error if the watcher cannot be created or a parent directory cannot be
/// watched.
pub fn watch_mesh_files(
    paths: &[String],
    on_change: impl Fn() + Send + 'static,
) -> anyhow::Result<()> {
    use notify::{RecursiveMode, Watcher};

    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    for p in paths {
        let parent = Path::new(p).parent().unwrap_or_else(|| Path::new("."));
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if !dirs.iter().any(|d| d == parent) {
            dirs.push(parent.to_path_buf());
        }
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| anyhow::anyhow!("failed to create mesh cert watcher: {e}"))?;
    for dir in &dirs {
        watcher
            .watch(dir, RecursiveMode::NonRecursive)
            .map_err(|e| anyhow::anyhow!("failed to watch mesh cert dir {}: {e}", dir.display()))?;
    }

    let watched_paths: Vec<String> = paths.to_vec();
    let mut last_digest = files_digest(&watched_paths);
    std::thread::Builder::new()
        .name("mesh-cert-watch".to_string())
        .spawn(move || {
            // Keep the watcher alive for the life of this thread (dropping it stops
            // watching).
            let _watcher = watcher;
            while let Ok(event) = rx.recv() {
                match event {
                    Ok(_) => {
                        // Debounce the burst of events a single re-projection emits.
                        std::thread::sleep(Duration::from_millis(200));
                        while rx.try_recv().is_ok() {}
                        // Only reload when the bytes actually changed — ignore spurious
                        // events from filesystems that emit them continuously.
                        let digest = files_digest(&watched_paths);
                        if digest != last_digest {
                            last_digest = digest;
                            on_change();
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "mesh cert watch error"),
                }
            }
            tracing::warn!("mesh cert watcher channel closed; hot-reload stopped");
        })
        .map_err(|e| anyhow::anyhow!("failed to spawn mesh cert watch thread: {e}"))?;

    Ok(())
}

/// A combined SHA-256 over the contents of `paths` (an unreadable file hashes as empty),
/// used to tell a real rotation from a spurious filesystem event.
fn files_digest(paths: &[String]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for p in paths {
        let bytes = std::fs::read(p).unwrap_or_default();
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests;
