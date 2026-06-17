//! Inter-node **forward** — the private mesh-mTLS link between Tunneller nodes.
//!
//! When a tenant connection lands on a node that does not own the tunnel, the node
//! dials the owner's forward listener (`node_addr` from `tunnel_routes`), sends a
//! tiny preamble `{slug, dest_port}`, then splices the raw L4 stream across. The
//! owner reads the preamble and hands the rest of the mTLS stream to its local
//! registry as a [`ForwardRequest`] — so from the tunnel handler's view a forwarded
//! connection is indistinguishable from a local one.
//!
//! The listener requires a client certificate chained to the mesh **trust bundle** (the
//! handshake *is* the authentication — it bypasses SNI, so it must be authenticated) and
//! additionally pins the peer's SPIFFE `scope == own scope` and `service == tunneller`;
//! the dialer presents this node's leaf and pins the peer as `tunneller` in this node's
//! scope via the mesh SPIFFE verifier, ignoring the (placeholder) SNI. Both the dialer
//! connector and the acceptor config hot-reload on leaf rotation.

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use wardnet_common::mtls::{self, ExpectedPeer, ReloadableServerConfig};

use crate::tunnel::{ForwardRequest, ForwardResult, TunnelRegistry};

/// Max concurrent in-flight inter-node forward connections (accept-storm guard).
const MAX_CONCURRENT_FORWARD: usize = 4096;
/// Upper bound on the preamble slug length (defensive — slugs are ≤32 chars).
const MAX_SLUG_LEN: usize = 64;
/// Placeholder SNI for the inter-node dialer. Mesh leaves carry no DNS SAN and the
/// SPIFFE verifier ignores the SNI, so this is never matched against the peer cert — it
/// only satisfies the `connect` API's `ServerName` argument.
const FORWARD_SNI_PLACEHOLDER: &str = "tunneller.mesh";

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

/// mTLS-backed [`InterNodeForwarder`] presenting this node's mesh leaf and pinning the
/// peer as `tunneller` in this node's scope (via the mesh SPIFFE verifier). The
/// connector lives in an [`ArcSwap`] so a rotated leaf can be swapped in without a
/// restart ([`reload`](Self::reload)).
pub struct MtlsForwarder {
    connector: ArcSwap<TlsConnector>,
    expected: ExpectedPeer,
    server_name: ServerName<'static>,
}

impl MtlsForwarder {
    /// Build the forwarder from this node's mesh PEM material, pinning `expected` as the
    /// peer identity it will accept on every dial.
    ///
    /// # Errors
    /// Returns an error if the PEM is malformed or the connector cannot be built.
    pub fn new(
        leaf_cert_pem: &[u8],
        leaf_key_pem: &[u8],
        trust_bundle_pem: &[u8],
        expected: ExpectedPeer,
    ) -> anyhow::Result<Arc<Self>> {
        let connector =
            Self::build_connector(leaf_cert_pem, leaf_key_pem, trust_bundle_pem, &expected)?;
        let server_name = ServerName::try_from(FORWARD_SNI_PLACEHOLDER.to_string())
            .expect("placeholder forward SNI is a valid DNS name");
        Ok(Arc::new(Self {
            connector: ArcSwap::from_pointee(connector),
            expected,
            server_name,
        }))
    }

    /// Rebuild the connector from rotated material and swap it in atomically. The pinned
    /// [`ExpectedPeer`] is preserved.
    ///
    /// # Errors
    /// Returns an error if the new connector cannot be built; the previous one is left
    /// in place on failure.
    pub fn reload(
        &self,
        leaf_cert_pem: &[u8],
        leaf_key_pem: &[u8],
        trust_bundle_pem: &[u8],
    ) -> anyhow::Result<()> {
        let connector = Self::build_connector(
            leaf_cert_pem,
            leaf_key_pem,
            trust_bundle_pem,
            &self.expected,
        )?;
        self.connector.store(Arc::new(connector));
        Ok(())
    }

    fn build_connector(
        leaf_cert_pem: &[u8],
        leaf_key_pem: &[u8],
        trust_bundle_pem: &[u8],
        expected: &ExpectedPeer,
    ) -> anyhow::Result<TlsConnector> {
        let config = mtls::client_config_from_pem(
            leaf_cert_pem,
            leaf_key_pem,
            trust_bundle_pem,
            expected.clone(),
        )?;
        Ok(TlsConnector::from(Arc::new(config)))
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
        let connector = self.connector.load_full();
        let tcp = TcpStream::connect(node_addr).await?;
        let mut peer = connector.connect(self.server_name.clone(), tcp).await?;
        write_preamble(&mut peer, slug, dest_port).await?;
        // Splice the raw L4 stream both ways until either side closes.
        tokio::io::copy_bidirectional(&mut client, &mut peer).await?;
        Ok(())
    }
}

/// Serve the inter-node forward listener over mutual TLS on `forward_listen_addr`. The
/// `server_config` holder is read once per accepted connection (so a leaf rotation takes
/// effect on new connections); after the handshake the peer's SPIFFE identity must be a
/// `tunneller` in `own_scope` (the scope-direction rule for a regional acceptor — other
/// scopes/services and other regions are already bundle-blocked) before its preamble is
/// read and the remaining mTLS stream is spliced into this node's local registry.
///
/// # Errors
/// Returns an error if the listener cannot be bound.
pub async fn serve_forward(
    forward_listen_addr: &str,
    server_config: Arc<ReloadableServerConfig>,
    registry: Arc<TunnelRegistry>,
    own_scope: String,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(forward_listen_addr).await?;
    tracing::info!(addr = %forward_listen_addr, "inter-node forward listener (mTLS) listening");

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_FORWARD));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "forward listener accept error");
                continue;
            }
        };
        let acceptor = TlsAcceptor::from(server_config.current());
        let registry = Arc::clone(&registry);
        let own_scope = own_scope.clone();
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("semaphore closed");
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    tracing::debug!(error = %e, %peer, "forward mTLS handshake rejected");
                    return;
                }
            };
            // Scope-direction rule: a regional acceptor admits only same-scope peers,
            // and the forward plane is same-service-only (`tunneller`). The chain is
            // already enforced by rustls; this pins the SPIFFE identity on top.
            let Some(peer_id) = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| mtls::peer_spiffe_id(certs).ok())
            else {
                tracing::debug!(%peer, "forward peer presented no parseable SPIFFE id, dropping");
                return;
            };
            if peer_id.service != "tunneller" || peer_id.scope != own_scope {
                tracing::debug!(
                    %peer,
                    peer_service = %peer_id.service,
                    peer_scope = %peer_id.scope,
                    %own_scope,
                    "forward peer rejected by scope-direction rule, dropping"
                );
                return;
            }
            handle_forward(tls, &registry).await;
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
