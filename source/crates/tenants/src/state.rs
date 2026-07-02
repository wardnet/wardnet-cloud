//! Shared application state injected into every handler via [`axum::extract::State`].
//!
//! Holds the [`TenantsService`] (which owns the repositories + JWT signer), the
//! offline JWT [`Verifier`] and [`ReplayCache`] (the [`AuthContext`] the auth layer
//! needs), and the [`Config`]. Cloning is cheap — everything is behind an [`Arc`].

use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;

use wardnet_common::auth::AuthContext;
use wardnet_common::ports::{BillingPort, PlanCatalog, SubscriptionCommands, SubscriptionReader};
use wardnet_common::replay_cache::ReplayCache;
use wardnet_common::token::Verifier;

use crate::config::Config;
use crate::identities::IdentitiesService;
use crate::service::TenantsService;

/// Cloneable handle to the service's shared state.
///
/// The license + payment aggregates are reached only through their `common` **ports**
/// (`dyn` trait objects injected by the composition root), never their concrete
/// services — so this crate (and its handlers) depend on `wardnet_common` alone, not
/// on `subscriptions`/`billing` (ADR-0010).
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    config: Config,
    tenants: Arc<TenantsService>,
    /// Entitlement reads over the license aggregate.
    subscriptions: Arc<dyn SubscriptionReader>,
    /// Account-plane subscription cancel (the one command the USER plane drives).
    subscription_commands: Arc<dyn SubscriptionCommands>,
    /// Hosted Checkout + change-plan + card-update + the provider webhook.
    billing: Arc<dyn BillingPort>,
    /// The plan-catalog read port (`GET /v1/plans`).
    plans: Arc<dyn PlanCatalog>,
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
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        config: Config,
        tenants: Arc<TenantsService>,
        subscriptions: Arc<dyn SubscriptionReader>,
        subscription_commands: Arc<dyn SubscriptionCommands>,
        billing: Arc<dyn BillingPort>,
        plans: Arc<dyn PlanCatalog>,
        identities: Arc<IdentitiesService>,
        verifier: Verifier,
    ) -> Self {
        let cookie_key = Key::from(config.cookie_key.as_bytes());
        Self(Arc::new(Inner {
            config,
            tenants,
            subscriptions,
            subscription_commands,
            billing,
            plans,
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

    /// The license aggregate's read port (entitlement / current subscription).
    #[must_use]
    pub fn subscriptions(&self) -> &dyn SubscriptionReader {
        self.0.subscriptions.as_ref()
    }

    /// The license aggregate's command port (account-plane cancel).
    #[must_use]
    pub fn subscription_commands(&self) -> &dyn SubscriptionCommands {
        self.0.subscription_commands.as_ref()
    }

    /// The payment aggregate's command port (Checkout / change-plan / card-update / webhook).
    #[must_use]
    pub fn billing(&self) -> &dyn BillingPort {
        self.0.billing.as_ref()
    }

    /// The plan-catalog read port (`GET /v1/plans`).
    #[must_use]
    pub fn plans(&self) -> &dyn PlanCatalog {
        self.0.plans.as_ref()
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
