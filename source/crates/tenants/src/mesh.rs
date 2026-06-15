//! Internal mesh-mTLS introspect listener.
//!
//! `POST /v1/introspect` is a **mesh-plane** endpoint (Tenants ↔ DDNS reaper): it
//! is served here over mutual TLS on a private internal address, **not** on the
//! public nginx-fronted router. mTLS *is* the authentication — only a peer
//! presenting a client certificate chained to the mesh CA completes the handshake;
//! there is no JWT/bearer layer. JWT is for external daemon requests; inter-service
//! mesh calls authenticate by certificate.

use axum::Router;
use axum::routing::post;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use wardnet_common::{mtls, serve};

use crate::api;
use crate::config::Config;
use crate::state::AppState;

/// Serve `POST /v1/introspect` over a mesh-mTLS listener bound to
/// `config.introspect_listen_addr`. The server presents its mesh leaf cert and
/// requires a client cert chained to the mesh CA (all from `config`'s PEM paths).
///
/// # Errors
/// Returns an error if the mesh PEM material cannot be read/parsed or the listener
/// cannot be bound.
pub async fn serve_introspect(config: &Config, state: AppState) -> anyhow::Result<()> {
    let ca = std::fs::read(&config.mesh_ca_path)
        .map_err(|e| anyhow::anyhow!("read mesh CA at {}: {e}", config.mesh_ca_path))?;
    let cert = std::fs::read(&config.mesh_cert_path)
        .map_err(|e| anyhow::anyhow!("read mesh cert at {}: {e}", config.mesh_cert_path))?;
    let key = std::fs::read(&config.mesh_key_path)
        .map_err(|e| anyhow::anyhow!("read mesh key at {}: {e}", config.mesh_key_path))?;

    let server_config = mtls::server_config_from_pem(&cert, &key, &ca)?;
    let acceptor = TlsAcceptor::from(server_config);
    let router = introspect_router(state);

    let listener = TcpListener::bind(&config.introspect_listen_addr).await?;
    tracing::info!(
        addr = %config.introspect_listen_addr,
        "mesh introspect listener (mTLS) listening"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "introspect listener accept error");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls) => {
                    if let Err(e) = serve::connection(tls, router, peer).await {
                        tracing::debug!(error = %e, %peer, "introspect connection error");
                    }
                }
                // A peer with no client cert, or one from a foreign CA, is rejected
                // here at the handshake — that is the mesh authentication boundary.
                Err(e) => tracing::debug!(error = %e, %peer, "introspect mTLS handshake rejected"),
            }
        });
    }
}

/// Build the single-route introspect [`Router`]. There is **no** `auth_layer`:
/// mutual TLS on the listener is the authentication.
pub fn introspect_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/introspect", post(api::introspect::introspect))
        .with_state(state)
}
