//! Shared application state injected into every handler via [`axum::extract::State`].
//!
//! Holds the [`TenantsService`] (which owns the repositories + JWT signer), the
//! offline JWT [`Verifier`] and [`ReplayCache`] (the [`AuthContext`] the auth layer
//! needs), and the [`Config`]. Cloning is cheap — everything is behind an [`Arc`].

use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;

use wardnet_common::auth::AuthContext;
use wardnet_common::replay_cache::ReplayCache;
use wardnet_common::token::Verifier;

use crate::config::Config;
use crate::identities::IdentitiesService;
use crate::service::TenantsService;
use crate::subscription::SubscriptionService;

/// Cloneable handle to the service's shared state.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    config: Config,
    tenants: Arc<TenantsService>,
    subscriptions: Arc<SubscriptionService>,
    identities: Arc<IdentitiesService>,
    verifier: Verifier,
    replay_cache: Arc<ReplayCache>,
    /// Symmetric key for the encrypted/signed cookie jar (WS-F web auth).
    cookie_key: Key,
}

impl AppState {
    /// Build the shared state. `config.cookie_key` must be ≥ 64 bytes (the `axum-extra`
    /// private jar requirement); `Config::from_env` validates this up front, so by the
    /// time we reach `Key::from` here the length is already guaranteed.
    #[must_use]
    pub fn new(
        config: Config,
        tenants: Arc<TenantsService>,
        subscriptions: Arc<SubscriptionService>,
        identities: Arc<IdentitiesService>,
        verifier: Verifier,
    ) -> Self {
        let cookie_key = Key::from(config.cookie_key.as_bytes());
        Self(Arc::new(Inner {
            config,
            tenants,
            subscriptions,
            identities,
            verifier,
            replay_cache: Arc::new(ReplayCache::new()),
            cookie_key,
        }))
    }

    /// The human/web authentication (Identities aggregate) service.
    #[must_use]
    pub fn identities(&self) -> &IdentitiesService {
        &self.0.identities
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.0.config
    }

    /// The tenant business-rule service.
    #[must_use]
    pub fn tenants(&self) -> &TenantsService {
        &self.0.tenants
    }

    /// The subscription/billing business-rule service.
    #[must_use]
    pub fn subscriptions(&self) -> &SubscriptionService {
        &self.0.subscriptions
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

/// Lets the `axum-extra` `PrivateCookieJar` / `SignedCookieJar` extractors pull the
/// signing key out of [`AppState`].
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.0.cookie_key.clone()
    }
}
