//! Shared application state injected into handlers via [`axum::extract::State`].
//!
//! Holds the [`DdnsService`], the offline JWT [`Verifier`] + [`ReplayCache`] (the
//! [`AuthContext`] the daemon auth layer needs), and the [`Config`]. Cheaply
//! cloneable: an [`Arc`] inner.

use std::sync::Arc;

use wardnet_common::auth::AuthContext;
use wardnet_common::replay_cache::ReplayCache;
use wardnet_common::token::Verifier;

use crate::config::Config;
use crate::service::DdnsService;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    config: Config,
    ddns: Arc<DdnsService>,
    verifier: Verifier,
    replay_cache: Arc<ReplayCache>,
}

impl AppState {
    #[must_use]
    pub fn new(config: Config, ddns: Arc<DdnsService>, verifier: Verifier) -> Self {
        Self(Arc::new(Inner {
            config,
            ddns,
            verifier,
            replay_cache: Arc::new(ReplayCache::new()),
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
}

impl AuthContext for AppState {
    fn verifier(&self) -> &Verifier {
        &self.0.verifier
    }

    fn replay_cache(&self) -> &ReplayCache {
        &self.0.replay_cache
    }
}
