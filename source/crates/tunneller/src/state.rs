//! Shared application state injected into handlers via [`axum::extract::State`].
//!
//! Holds the per-node tunnel registry, the regional `tunnel_routes` repository, the
//! Tenants resolver (the routing policy's reads), this node's advertised forward
//! address, and the offline JWT [`Verifier`] + [`ReplayCache`] (the [`AuthContext`]
//! the daemon auth layer needs). Cheaply cloneable: an [`Arc`] inner.
//!
//! Identity is **JWT-only** here — the global identity DB lives in Tenants, so this
//! bin verifies daemon identity JWTs offline (no DB).

use std::sync::Arc;

use wardnet_common::auth::AuthContext;
use wardnet_common::replay_cache::ReplayCache;
use wardnet_common::token::Verifier;

use crate::config::Config;
use crate::mesh::TenantsResolver;
use crate::repository::TunnelRouteRepository;
use crate::tunnel::TunnelRegistry;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    config: Config,
    registry: Arc<TunnelRegistry>,
    routes: Arc<dyn TunnelRouteRepository>,
    tenants: Arc<dyn TenantsResolver>,
    /// This node's advertised forward address — the `node_addr` it writes into every
    /// `tunnel_routes` row it owns.
    node_addr: String,
    verifier: Verifier,
    replay_cache: Arc<ReplayCache>,
}

impl AppState {
    #[must_use]
    pub fn new(
        config: Config,
        registry: Arc<TunnelRegistry>,
        routes: Arc<dyn TunnelRouteRepository>,
        tenants: Arc<dyn TenantsResolver>,
        verifier: Verifier,
    ) -> Self {
        let node_addr = config.forward_advertise_addr.clone();
        Self(Arc::new(Inner {
            config,
            registry,
            routes,
            tenants,
            node_addr,
            verifier,
            replay_cache: Arc::new(ReplayCache::new()),
        }))
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.0.config
    }

    /// The per-node tunnel registry.
    #[must_use]
    pub fn registry(&self) -> Arc<TunnelRegistry> {
        Arc::clone(&self.0.registry)
    }

    /// The regional `tunnel_routes` repository.
    #[must_use]
    pub fn routes(&self) -> Arc<dyn TunnelRouteRepository> {
        Arc::clone(&self.0.routes)
    }

    /// The Tenants resolver backing the routing policy.
    #[must_use]
    pub fn tenants(&self) -> Arc<dyn TenantsResolver> {
        Arc::clone(&self.0.tenants)
    }

    /// This node's advertised forward address.
    #[must_use]
    pub fn node_addr(&self) -> &str {
        &self.0.node_addr
    }
}

impl AuthContext for AppState {
    fn verifier(&self) -> &Verifier {
        &self.0.verifier
    }

    fn replay_cache(&self) -> &ReplayCache {
        &self.0.replay_cache
    }
}
