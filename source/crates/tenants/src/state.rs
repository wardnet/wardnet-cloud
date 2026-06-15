use std::sync::Arc;

use wardnet_common::replay_cache::ReplayCache;
use wardnet_common::token::Verifier;

use crate::config::Config;
use crate::service::TenantsService;

/// Shared application state injected into every Tenants handler via
/// [`axum::extract::State`].
///
/// Holds the [`TenantsService`] (which owns its identity + challenge repos), the
/// offline JWT [`Verifier`], and the replay cache the auth middleware uses. Cloning
/// is cheap — the inner data lives behind an [`Arc`].
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    config: Config,
    /// Global identity + naming service (registration, challenges, auth, refresh,
    /// deregistration, introspection).
    tenants: Arc<TenantsService>,
    /// Offline verifier for Tenants-signed identity JWTs (the JWT path of auth).
    verifier: Verifier,
    /// In-memory replay-prevention cache (keyed `{install_id}:{timestamp}:{body_hash}`).
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

    /// The global identity + naming service.
    #[must_use]
    pub fn tenants(&self) -> &TenantsService {
        &self.0.tenants
    }

    /// The offline verifier for Tenants-signed identity JWTs.
    #[must_use]
    pub fn jwt_verifier(&self) -> &Verifier {
        &self.0.verifier
    }

    #[must_use]
    pub fn replay_cache(&self) -> &ReplayCache {
        &self.0.replay_cache
    }
}
