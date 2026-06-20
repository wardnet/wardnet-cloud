//! Internal mesh-mTLS **listener** (Tenants ↔ DDNS provisioner/reaper).
//!
//! This module is the mesh-plane *transport*: it terminates mutual TLS on a
//! private address and serves the SERVICE-plane work-queue API
//! ([`crate::api::reconcile`]). A peer must present a client certificate chained
//! to the mesh CA to complete the handshake — that handshake *is* the `SERVICE`
//! authentication, and each accepted connection is stamped with a
//! [`ServiceIdentity`] before the reconcile router's `authenticate(SERVICE)`
//! layer runs.
//!
//! No API surface lives here; "mesh" names the mTLS transport, not a route group.

use std::sync::Arc;

use axum::Extension;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use wardnet_common::auth::ServiceIdentity;
use wardnet_common::mtls::{self, ReloadableServerConfig};
use wardnet_common::serve;

use crate::api;
use crate::state::AppState;

/// Max concurrent in-flight mesh connections (accept-storm guard).
const MAX_CONCURRENT_MESH: usize = 1024;

/// Serve the mesh work-queue over mutual TLS on `mesh_listen_addr`.
///
/// Tenants is a **global**-scope acceptor: rustls enforces the client-cert chain against
/// the trust bundle, and any in-bundle, scope-valid peer is admitted (the global
/// acceptor imposes no scope-direction restriction — out-of-region peers are already
/// bundle-blocked). Each accepted connection is stamped with the peer's parsed
/// [`ServiceIdentity`] before the reconcile router's `authenticate(SERVICE)` layer runs.
/// The `server_config` holder is read once per connection so a rotated leaf takes effect
/// on new connections.
///
/// # Errors
/// Returns an error if the listener cannot be bound.
pub async fn serve_mesh(
    mesh_listen_addr: &str,
    server_config: Arc<ReloadableServerConfig>,
    state: AppState,
) -> anyhow::Result<()> {
    // The mesh listener serves the reconcile work-queue plus the SERVICE-plane
    // resource reads (`GET /v1/networks/{id}`, `GET /v1/tenants/{id}`) the Tunneller
    // routing policy consumes. All carry `authenticate(SERVICE)`.
    let router = api::reconcile::router(state.clone())
        .merge(api::network::router(state.clone()))
        .merge(api::tenant::router(state));

    let listener = TcpListener::bind(mesh_listen_addr).await?;
    tracing::info!(addr = %mesh_listen_addr, "mesh work-queue listener (mTLS) listening");

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_MESH));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "mesh listener accept error");
                continue;
            }
        };
        let acceptor = TlsAcceptor::from(server_config.current());
        let router = router.clone();
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("semaphore closed");
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    tracing::debug!(error = %e, %peer, "mesh mTLS handshake rejected");
                    return;
                }
            };
            // The handshake validated a chain to the trust bundle; parse the peer's
            // SPIFFE identity and stamp it so `authenticate(SERVICE)` accepts the route.
            let Some(peer_id) = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| mtls::peer_spiffe_id(certs).ok())
            else {
                tracing::debug!(%peer, "mesh peer presented no parseable SPIFFE id, dropping");
                return;
            };
            let conn_router = router.layer(Extension(ServiceIdentity::from(peer_id)));
            if let Err(e) = serve::connection(tls, conn_router, peer).await {
                tracing::debug!(error = %e, %peer, "mesh connection error");
            }
        });
    }
}
