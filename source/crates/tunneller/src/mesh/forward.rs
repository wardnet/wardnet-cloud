//! Inter-node **forward** — the private mesh-mTLS link between Tunneller nodes.
//!
//! When a tenant connection lands on a node that does not own the tunnel, the node
//! dials the owner's forward listener (`node_addr` from `tunnel_routes`), sends a
//! tiny preamble `{slug, dest_port}`, then splices the raw L4 stream across. The
//! owner reads the preamble and hands the rest of the mTLS stream to its local
//! registry as a [`ForwardRequest`] — so from the tunnel handler's view a forwarded
//! connection is indistinguishable from a local one.
//!
//! The listener requires a client certificate chained to the mesh CA (the handshake
//! *is* the authentication — it bypasses SNI, so it must be authenticated); the
//! dialer presents this node's leaf and verifies the peer's leaf against the same
//! mesh root under the shared [`Config::forward_server_name`] SAN.

use std::sync::Arc;

use async_trait::async_trait;
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::Config;
use crate::tunnel::{ForwardRequest, ForwardResult, TunnelRegistry};

/// Max concurrent in-flight inter-node forward connections (accept-storm guard).
const MAX_CONCURRENT_FORWARD: usize = 4096;
/// Upper bound on the preamble slug length (defensive — slugs are ≤32 chars).
const MAX_SLUG_LEN: usize = 64;

/// Cross-node forwarding seam: hand a local client stream to the node that owns the
/// tunnel for `slug`. Mocked in `LocalRouter` unit tests.
#[async_trait]
pub trait InterNodeForwarder: Send + Sync {
    /// Dial `node_addr`, announce `{slug, dest_port}`, and splice `client` across.
    ///
    /// # Errors
    /// Returns an error if the peer cannot be dialed, the handshake fails, or the
    /// splice ends abnormally.
    async fn forward(
        &self,
        node_addr: &str,
        slug: &str,
        dest_port: u16,
        client: TcpStream,
    ) -> anyhow::Result<()>;
}

/// mTLS-backed [`InterNodeForwarder`] presenting this node's mesh leaf.
pub struct MtlsForwarder {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl MtlsForwarder {
    /// Build the forwarder from this node's mesh PEM material and the server name
    /// every Tunneller leaf carries as a SAN.
    ///
    /// # Errors
    /// Returns an error if the PEM is malformed or `server_name` is not a valid DNS
    /// name.
    pub fn new(
        leaf_cert_pem: &[u8],
        leaf_key_pem: &[u8],
        mesh_root_pem: &[u8],
        server_name: &str,
    ) -> anyhow::Result<Self> {
        let config = client_config_from_pem(leaf_cert_pem, leaf_key_pem, mesh_root_pem)?;
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| anyhow::anyhow!("invalid forward server name: {e}"))?;
        Ok(Self {
            connector: TlsConnector::from(config),
            server_name,
        })
    }
}

#[async_trait]
impl InterNodeForwarder for MtlsForwarder {
    async fn forward(
        &self,
        node_addr: &str,
        slug: &str,
        dest_port: u16,
        mut client: TcpStream,
    ) -> anyhow::Result<()> {
        let tcp = TcpStream::connect(node_addr).await?;
        let mut peer = self
            .connector
            .connect(self.server_name.clone(), tcp)
            .await?;
        write_preamble(&mut peer, slug, dest_port).await?;
        // Splice the raw L4 stream both ways until either side closes.
        tokio::io::copy_bidirectional(&mut client, &mut peer).await?;
        Ok(())
    }
}

/// Build a rustls [`ClientConfig`] that presents `leaf` and trusts **only** the mesh
/// root for the peer's server certificate.
///
/// # Errors
/// Returns an error if any PEM is malformed/empty or the config cannot be built.
pub fn client_config_from_pem(
    leaf_cert_pem: &[u8],
    leaf_key_pem: &[u8],
    mesh_root_pem: &[u8],
) -> anyhow::Result<Arc<ClientConfig>> {
    let roots = wardnet_common::mtls::root_store_from_pem(mesh_root_pem)?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &leaf_cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse mesh leaf certificate PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("mesh leaf certificate PEM contained no certificates");
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &leaf_key_pem[..])
        .map_err(|e| anyhow::anyhow!("failed to parse mesh leaf key PEM: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("mesh leaf key PEM contained no private key"))?;

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("failed to build mesh client config: {e}"))?;
    Ok(Arc::new(config))
}

/// Serve the inter-node forward listener over mutual TLS on
/// `config.forward_listen_addr`. Each accepted connection's preamble is read and the
/// remaining mTLS stream is spliced into this node's local registry.
///
/// # Errors
/// Returns an error if the mesh PEM cannot be read/parsed or the listener cannot be
/// bound.
pub async fn serve_forward(config: &Config, registry: Arc<TunnelRegistry>) -> anyhow::Result<()> {
    let ca = std::fs::read(&config.mesh_ca_path)
        .map_err(|e| anyhow::anyhow!("read mesh CA at {}: {e}", config.mesh_ca_path))?;
    let cert = std::fs::read(&config.mesh_cert_path)
        .map_err(|e| anyhow::anyhow!("read mesh cert at {}: {e}", config.mesh_cert_path))?;
    let key = std::fs::read(&config.mesh_key_path)
        .map_err(|e| anyhow::anyhow!("read mesh key at {}: {e}", config.mesh_key_path))?;

    let server_config = wardnet_common::mtls::server_config_from_pem(&cert, &key, &ca)?;
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind(&config.forward_listen_addr).await?;
    tracing::info!(addr = %config.forward_listen_addr, "inter-node forward listener (mTLS) listening");

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_FORWARD));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "forward listener accept error");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let registry = Arc::clone(&registry);
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("semaphore closed");
        tokio::spawn(async move {
            let _permit = permit;
            match acceptor.accept(stream).await {
                Ok(tls) => handle_forward(tls, &registry).await,
                Err(e) => tracing::debug!(error = %e, %peer, "forward mTLS handshake rejected"),
            }
        });
    }
}

/// Read the preamble off an accepted forward stream and splice the rest into the
/// local tunnel for `slug` (fail-closed: an unknown slug drops the connection).
async fn handle_forward<S>(mut tls: S, registry: &Arc<TunnelRegistry>)
where
    S: crate::tunnel::TunnelStream,
{
    let (slug, dest_port) = match read_preamble(&mut tls).await {
        Ok(preamble) => preamble,
        Err(e) => {
            tracing::debug!(error = %e, "forward preamble read failed, dropping");
            return;
        }
    };
    let req = ForwardRequest {
        stream: Box::new(tls),
        dest_port,
    };
    match registry.forward(&slug, req) {
        ForwardResult::Accepted => {}
        ForwardResult::NotConnected => {
            tracing::debug!(slug = %slug, "no local tunnel for forwarded slug, dropping");
        }
        ForwardResult::BufferFull => {
            tracing::debug!(slug = %slug, "forwarded tunnel buffer full, dropping");
        }
    }
}

/// Write the `{slug, dest_port}` preamble: `[slug_len: u16][slug][dest_port: u16]`.
///
/// # Errors
/// Returns an error if the slug is too long or the write fails.
pub async fn write_preamble<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    slug: &str,
    dest_port: u16,
) -> anyhow::Result<()> {
    let bytes = slug.as_bytes();
    if bytes.len() > MAX_SLUG_LEN {
        anyhow::bail!("slug too long for preamble: {} bytes", bytes.len());
    }
    let len = u16::try_from(bytes.len()).expect("slug length fits u16 (bounded above)");
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(bytes).await?;
    w.write_all(&dest_port.to_be_bytes()).await?;
    w.flush().await?;
    Ok(())
}

/// Read the `{slug, dest_port}` preamble written by [`write_preamble`].
///
/// # Errors
/// Returns an error if the stream ends early or the slug length is out of bounds.
pub async fn read_preamble<R: AsyncReadExt + Unpin>(r: &mut R) -> anyhow::Result<(String, u16)> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_SLUG_LEN {
        anyhow::bail!("preamble slug length out of bounds: {len}");
    }
    let mut slug = vec![0u8; len];
    r.read_exact(&mut slug).await?;
    let mut port_buf = [0u8; 2];
    r.read_exact(&mut port_buf).await?;
    let slug =
        String::from_utf8(slug).map_err(|e| anyhow::anyhow!("preamble slug not UTF-8: {e}"))?;
    Ok((slug, u16::from_be_bytes(port_buf)))
}
