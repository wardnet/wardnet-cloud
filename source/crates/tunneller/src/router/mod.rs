//! Inbound-stream routing: the seam between the SNI demuxer and the tunnels.
//!
//! The SNI demuxer hands every inbound stream to a [`TunnelRouter`] keyed on the
//! vanity slug — it never touches the in-memory [`TunnelRegistry`] directly. The
//! sole impl, [`LocalRouter`], short-circuits slugs owned by **this** node into the
//! local registry and forwards everything else over the inter-node mesh link to the
//! node named in the `tunnel_routes` table. Forwarding **fails closed**: a slug with
//! no route, or one whose owning node's registry no longer holds it, is dropped.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::mesh::InterNodeForwarder;
use crate::repository::TunnelRouteRepository;
use crate::tunnel::{ForwardRequest, ForwardResult, TunnelRegistry};

/// Routes an inbound client stream for a slug to its tunnel (local or remote).
#[async_trait]
pub trait TunnelRouter: Send + Sync {
    /// Route `stream` (destined for `dest_port`) to the tunnel for `slug`. Infallible
    /// from the caller's view: an unroutable stream is logged and dropped.
    async fn route(&self, slug: &str, stream: TcpStream, dest_port: u16);
}

/// The node-local [`TunnelRouter`]: local registry first, else inter-node forward.
pub struct LocalRouter {
    registry: Arc<TunnelRegistry>,
    routes: Arc<dyn TunnelRouteRepository>,
    forwarder: Arc<dyn InterNodeForwarder>,
    /// This node's advertised forward address (its own `node_addr` in the table).
    node_addr: String,
}

impl LocalRouter {
    #[must_use]
    pub fn new(
        registry: Arc<TunnelRegistry>,
        routes: Arc<dyn TunnelRouteRepository>,
        forwarder: Arc<dyn InterNodeForwarder>,
        node_addr: String,
    ) -> Self {
        Self {
            registry,
            routes,
            forwarder,
            node_addr,
        }
    }
}

#[async_trait]
impl TunnelRouter for LocalRouter {
    async fn route(&self, slug: &str, stream: TcpStream, dest_port: u16) {
        // 1. Local tunnel: hand straight to the registry.
        if self.registry.is_connected(slug) {
            let req = ForwardRequest {
                stream: Box::new(stream),
                dest_port,
            };
            match self.registry.forward(slug, req) {
                ForwardResult::Accepted => {}
                // Raced an unregister between the check and the send.
                ForwardResult::NotConnected => {
                    tracing::debug!(slug, "local tunnel vanished mid-route, dropping");
                }
                ForwardResult::BufferFull => {
                    tracing::debug!(slug, "local tunnel buffer full, dropping");
                }
            }
            return;
        }

        // 2. Remote tunnel: forward to the node named in tunnel_routes.
        match self.routes.find_by_slug(slug).await {
            Ok(Some(route)) if route.node_addr != self.node_addr => {
                if let Err(e) = self
                    .forwarder
                    .forward(&route.node_addr, slug, dest_port, stream)
                    .await
                {
                    tracing::debug!(slug, node = %route.node_addr, error = %e, "inter-node forward failed, dropping");
                }
            }
            // The table says we own it, but our registry does not — a stale row
            // (this node restarted; the daemon has not reconnected yet). Fail closed.
            Ok(Some(_)) => {
                tracing::debug!(slug, "stale local route (no live tunnel), dropping");
            }
            Ok(None) => {
                tracing::debug!(slug, "no route for slug, dropping");
            }
            Err(e) => {
                tracing::warn!(slug, error = %e, "tunnel_routes lookup failed, dropping");
            }
        }
    }
}

#[cfg(test)]
mod tests;
