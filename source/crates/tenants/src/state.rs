//! Shared application state injected into every handler via [`axum::extract::State`].
//!
//! Holds the [`TenantsService`] (which owns the repositories + JWT signer), the
//! offline JWT [`Verifier`] and [`ReplayCache`] (the [`AuthContext`] the auth layer
//! needs), and the [`Config`]. Cloning is cheap — everything is behind an [`Arc`].

use std::sync::Arc;

use wardnet_common::auth::AuthContext;
use wardnet_common::replay_cache::ReplayCache;
use wardnet_common::token::Verifier;

use crate::config::Config;
use crate::service::TenantsService;

/// Cloneable handle to the service's shared state.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    config: Config,
    tenants: Arc<TenantsService>,
    verifier: Verifier,
    replay_cache: Arc<ReplayCache>,
}

impl AppState {
    #[must_use]
    pub fn new(config: Config, tenants: Arc<TenantsService>, verifier: Verifier) -> Self {
        Self(Arc::new(Inner {
            config,
            tenants,
            verifier,
            replay_cache: Arc::new(ReplayCache::new()),
        }))
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.0.config
    }

    /// The business-rule service.
    #[must_use]
    pub fn tenants(&self) -> &TenantsService {
        &self.0.tenants
    }

    /// The replay cache (used by the bootstrap token endpoint's `PoP` check).
    #[must_use]
    pub fn replay_cache(&self) -> &ReplayCache {
        &self.0.replay_cache
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
