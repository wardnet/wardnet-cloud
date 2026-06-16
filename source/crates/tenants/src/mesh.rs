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
use wardnet_common::{mtls, serve};

use crate::api;
use crate::config::Config;
use crate::state::AppState;

/// Max concurrent in-flight mesh connections (accept-storm guard).
const MAX_CONCURRENT_MESH: usize = 1024;

/// Serve the mesh work-queue over mutual TLS on `config.mesh_listen_addr`.
///
/// # Errors
/// Returns an error if the mesh PEM material cannot be read/parsed or the listener
/// cannot be bound.
pub async fn serve_mesh(config: &Config, state: AppState) -> anyhow::Result<()> {
    let ca = std::fs::read(&config.mesh_ca_path)
        .map_err(|e| anyhow::anyhow!("read mesh CA at {}: {e}", config.mesh_ca_path))?;
    let cert = std::fs::read(&config.mesh_cert_path)
        .map_err(|e| anyhow::anyhow!("read mesh cert at {}: {e}", config.mesh_cert_path))?;
    let key = std::fs::read(&config.mesh_key_path)
        .map_err(|e| anyhow::anyhow!("read mesh key at {}: {e}", config.mesh_key_path))?;

    let server_config = mtls::server_config_from_pem(&cert, &key, &ca)?;
    let acceptor = TlsAcceptor::from(server_config);
    let router = api::reconcile::router(state);

    let listener = TcpListener::bind(&config.mesh_listen_addr).await?;
    tracing::info!(addr = %config.mesh_listen_addr, "mesh work-queue listener (mTLS) listening");

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_MESH));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "mesh listener accept error");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("semaphore closed");
        tokio::spawn(async move {
            let _permit = permit;
            match acceptor.accept(stream).await {
                Ok(tls) => {
                    // The handshake validated a mesh-CA client cert; stamp the
                    // service identity so `authenticate(SERVICE)` accepts the route.
                    let conn_router = router.layer(Extension(ServiceIdentity {
                        subject: String::new(),
                    }));
                    if let Err(e) = serve::connection(tls, conn_router, peer).await {
                        tracing::debug!(error = %e, %peer, "mesh connection error");
                    }
                }
                Err(e) => tracing::debug!(error = %e, %peer, "mesh mTLS handshake rejected"),
            }
        });
    }
}
