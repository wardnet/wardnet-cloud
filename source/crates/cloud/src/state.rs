use std::sync::Arc;

use wardnet_common::replay_cache::ReplayCache;
use wardnet_common::token::Verifier;

use crate::config::Config;
use crate::service::DdnsService;
use crate::tunnel::TunnelRegistry;

/// Shared application state injected into every Axum handler via
/// [`axum::extract::State`].
///
/// Holds the **service layer**, not repositories — handlers call services, and
/// each service owns its own repositories (see [`crate::service`]). Cloning is
/// cheap: the inner data lives behind an [`Arc`].
///
/// Identity authentication here is **JWT-only**: the global identity DB lives in
/// the Tenants service, so this bin verifies daemon identity JWTs offline (no DB)
/// — it holds no `TenantsService`.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    config: Config,
    /// Regional DNS operational plane (Cloudflare records).
    ddns: Arc<DdnsService>,
    /// Offline verifier for Tenants-signed identity JWTs.
    verifier: Verifier,
    /// In-memory replay-prevention cache, keyed
    /// `"{install_id}:{timestamp}:{body_hash}"`.
    replay_cache: Arc<ReplayCache>,
    /// Registry of active Pi reverse-tunnel WebSocket connections.
    tunnel_registry: Arc<TunnelRegistry>,
}

impl AppState {
    #[must_use]
    pub fn new(
        config: Config,
        ddns: Arc<DdnsService>,
        verifier: Verifier,
        tunnel_registry: Arc<TunnelRegistry>,
    ) -> Self {
        Self(Arc::new(Inner {
            config,
            ddns,
            verifier,
            replay_cache: Arc::new(ReplayCache::new()),
            tunnel_registry,
        }))
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.0.config
    }

    /// The regional DNS operational service.
    #[must_use]
    pub fn ddns(&self) -> &DdnsService {
        &self.0.ddns
    }

    /// The offline verifier for Tenants-signed identity JWTs.
    #[must_use]
    pub(crate) fn jwt_verifier(&self) -> &Verifier {
        &self.0.verifier
    }

    #[must_use]
    pub(crate) fn replay_cache(&self) -> &ReplayCache {
        &self.0.replay_cache
    }

    /// Returns a cloned `Arc` to the tunnel registry.
    #[must_use]
    pub fn tunnel_registry(&self) -> Arc<TunnelRegistry> {
        Arc::clone(&self.0.tunnel_registry)
    }
}
