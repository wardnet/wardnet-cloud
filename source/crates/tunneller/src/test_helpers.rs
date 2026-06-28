//! Shared test fixtures: deterministic JWT/daemon keypairs, in-memory mocks for the
//! routes repository + Tenants resolver, contract-view builders, and an
//! [`AppState`] builder for the integration tests in `tests/`.
//!
//! Doc-hidden and **not** `cfg(test)` so the integration tests (a separate crate)
//! can reach these too; it carries no extra production dependencies beyond the
//! regular `ed25519-dalek` / `base64`. (A dedicated `wardnet-test-support` crate is
//! the eventual home.)

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;

use wardnet_common::contract::{
    Entitlement, NetworkView, ProvisioningState, SubscriptionStatus, SubscriptionView, TenantView,
};
use wardnet_common::token::{Signer, Verifier};

use crate::config::Config;
use crate::mesh::TenantsResolver;
use crate::repository::{TunnelRoute, TunnelRouteRepository};
use crate::state::AppState;
use crate::tunnel::TunnelRegistry;

// ── Key material ────────────────────────────────────────────────────────────────

/// A deterministic `EdDSA` JWT keypair as `(private_pkcs8_pem, public_spki_pem)`,
/// derived from `seed`.
#[must_use]
pub fn jwt_keypair_pem(seed: u8) -> (String, String) {
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};

    let signing = SigningKey::from_bytes(&[seed; 32]);
    let private_pem = signing
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode JWT private key PEM")
        .to_string();
    let public_pem = signing
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("encode JWT public key PEM");
    (private_pem, public_pem)
}

/// A deterministic daemon request-signing keypair plus the base64 `cnf` of its
/// public key, derived from `seed`.
#[must_use]
pub fn daemon_keypair(seed: u8) -> (SigningKey, String) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let cnf = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
    (key, cnf)
}

/// A `Signer` over the seed keypair — lets tests mint JWTs the built [`AppState`]'s
/// verifier accepts.
#[must_use]
pub fn test_signer(seed: u8) -> Signer {
    Signer::from_pem(jwt_keypair_pem(seed).0.as_bytes(), None).unwrap()
}

// ── Contract-view builders ───────────────────────────────────────────────────────

/// Build a [`NetworkView`] with the given lifecycle state.
#[must_use]
pub fn network_view(
    id: &str,
    slug: &str,
    tenant_id: &str,
    state: ProvisioningState,
) -> NetworkView {
    NetworkView {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        slug: slug.to_string(),
        display_name: slug.to_string(),
        region: "use1".to_string(),
        provisioning_state: state,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Build a [`TenantView`] with the given subscription status.
#[must_use]
pub fn tenant_view(id: &str, status: SubscriptionStatus) -> TenantView {
    let now = Utc::now();
    TenantView {
        id: id.to_string(),
        email: format!("{id}@example.com"),
        subscription: Some(SubscriptionView {
            id: format!("sub-{id}"),
            status,
            entitlement: Entitlement::DEFAULT,
            trial_expires_at: None,
            current_period_end: None,
            created_at: now,
            updated_at: now,
        }),
        created_at: now,
    }
}

// ── Mock Tenants resolver ─────────────────────────────────────────────────────────

/// In-memory [`TenantsResolver`]. `Clone` shares the same backing maps.
#[derive(Clone, Default)]
pub struct MockTenants {
    networks: Arc<Mutex<HashMap<String, NetworkView>>>,
    tenants: Arc<Mutex<HashMap<String, TenantView>>>,
    fail: Arc<AtomicBool>,
}

impl MockTenants {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a network (keyed by its id).
    pub fn seed_network(&self, view: NetworkView) {
        self.networks.lock().unwrap().insert(view.id.clone(), view);
    }

    /// Seed a tenant (keyed by its id).
    pub fn seed_tenant(&self, view: TenantView) {
        self.tenants.lock().unwrap().insert(view.id.clone(), view);
    }

    /// Make every read fail (the reaper's "skip on transient error" path).
    pub fn fail_reads(&self) {
        self.fail.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl TenantsResolver for MockTenants {
    async fn get_network(&self, id: &str) -> anyhow::Result<Option<NetworkView>> {
        if self.fail.load(Ordering::SeqCst) {
            anyhow::bail!("forced network read failure");
        }
        Ok(self.networks.lock().unwrap().get(id).cloned())
    }

    async fn get_tenant(&self, id: &str) -> anyhow::Result<Option<TenantView>> {
        if self.fail.load(Ordering::SeqCst) {
            anyhow::bail!("forced tenant read failure");
        }
        Ok(self.tenants.lock().unwrap().get(id).cloned())
    }
}

// ── In-memory routes repository ───────────────────────────────────────────────────

/// In-memory [`TunnelRouteRepository`] mirroring the SQL own-node guards. `Clone`
/// shares the same backing store.
#[derive(Clone, Default)]
pub struct InMemoryRoutes(Arc<Mutex<HashMap<String, TunnelRoute>>>);

impl InMemoryRoutes {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a row for assertions.
    #[must_use]
    pub fn get(&self, slug: &str) -> Option<TunnelRoute> {
        self.0.lock().unwrap().get(slug).cloned()
    }

    /// All rows, for assertions.
    #[must_use]
    pub fn all(&self) -> Vec<TunnelRoute> {
        self.0.lock().unwrap().values().cloned().collect()
    }

    /// Seed a row directly (e.g. with a stale `last_seen` for the TTL-reaper test).
    pub fn seed(&self, route: TunnelRoute) {
        self.0.lock().unwrap().insert(route.slug.clone(), route);
    }
}

#[async_trait]
impl TunnelRouteRepository for InMemoryRoutes {
    async fn upsert(
        &self,
        slug: &str,
        node_addr: &str,
        network_id: &str,
        tenant_id: &str,
    ) -> anyhow::Result<()> {
        self.0.lock().unwrap().insert(
            slug.to_string(),
            TunnelRoute {
                slug: slug.to_string(),
                node_addr: node_addr.to_string(),
                network_id: network_id.to_string(),
                tenant_id: tenant_id.to_string(),
                last_seen: Utc::now(),
            },
        );
        Ok(())
    }

    async fn delete(&self, slug: &str, node_addr: &str) -> anyhow::Result<bool> {
        let mut map = self.0.lock().unwrap();
        if map.get(slug).is_some_and(|r| r.node_addr == node_addr) {
            map.remove(slug);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn find_by_slug(&self, slug: &str) -> anyhow::Result<Option<TunnelRoute>> {
        Ok(self.0.lock().unwrap().get(slug).cloned())
    }

    async fn list_owned(&self, node_addr: &str) -> anyhow::Result<Vec<TunnelRoute>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.node_addr == node_addr)
            .cloned()
            .collect())
    }

    async fn touch(&self, slug: &str, node_addr: &str) -> anyhow::Result<bool> {
        let mut map = self.0.lock().unwrap();
        if let Some(row) = map.get_mut(slug)
            && row.node_addr == node_addr
        {
            row.last_seen = Utc::now();
            return Ok(true);
        }
        Ok(false)
    }

    async fn reap_expired(&self, deadline: DateTime<Utc>) -> anyhow::Result<u64> {
        let mut map = self.0.lock().unwrap();
        let before = map.len();
        map.retain(|_, r| r.last_seen >= deadline);
        Ok((before - map.len()) as u64)
    }
}

// ── Config + AppState ─────────────────────────────────────────────────────────────

/// The `node_addr` the mock-backed [`AppState`] advertises.
pub const TEST_NODE_ADDR: &str = "node-a.tunneller.mesh:9444";

/// A throwaway [`Config`] (no real listeners/PEM are opened in mock-backed tests).
#[must_use]
pub fn test_config() -> Config {
    Config {
        api_listen_addr: "127.0.0.1:0".to_string(),
        https_listen_addr: "127.0.0.1:0".to_string(),
        dot_listen_addr: "127.0.0.1:0".to_string(),
        database_url: "postgres://ignored".to_string(),
        mesh_base_url: "https://tenants.mesh:9443".to_string(),
        trust_bundle_path: "/dev/null".to_string(),
        leaf_cert_path: "/dev/null".to_string(),
        leaf_key_path: "/dev/null".to_string(),
        forward_listen_addr: "127.0.0.1:0".to_string(),
        forward_advertise_addr: TEST_NODE_ADDR.to_string(),
        region: "use1".to_string(),
        subdomain_parent: "my.wardnet.services".to_string(),
        reconcile_interval_secs: 30,
        reconcile_jitter_secs: 0,
        route_ttl_secs: 120,
        ttl_reaper_interval_secs: 60,
    }
}

/// Build an [`AppState`] backed by the given mocks, with a verifier over `seed`'s
/// keypair (so `test_signer(seed)`-minted tokens are accepted).
#[must_use]
pub fn build_state(
    seed: u8,
    registry: Arc<TunnelRegistry>,
    routes: Arc<dyn TunnelRouteRepository>,
    tenants: Arc<dyn TenantsResolver>,
) -> AppState {
    let verifier = Verifier::from_pem(jwt_keypair_pem(seed).1.as_bytes(), "tunneller").unwrap();
    AppState::new(test_config(), registry, routes, tenants, verifier)
}
