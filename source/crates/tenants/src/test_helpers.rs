//! Shared test fixtures: a deterministic JWT keypair, in-memory mock repositories
//! over a single shared store (so cross-aggregate invariants hold), and an
//! [`AppState`] builder. Doc-hidden; used by both unit tests and the integration
//! tests in `tests/`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;

use wardnet_common::token::{Signer, Verifier};

use crate::config::Config;
use crate::repository::daemon::{Daemon, DaemonRepository};
use crate::repository::enrollment::{EnrollOutcome, EnrollmentRepository};
use crate::repository::network::{
    Network, NetworkRepository, ProvisioningState, RegisterNetworkOutcome,
};
use crate::repository::tenant::{
    CreateTenantOutcome, Entitlement, SubscriptionStatus, Tenant, TenantRepository,
};
use crate::service::TenantsService;
use crate::state::AppState;

// ── Key material ────────────────────────────────────────────────────────────────

/// A deterministic `EdDSA` JWT keypair as `(private_pkcs8_pem, public_spki_pem)`,
/// derived from `seed`. Distinct seeds give independent keypairs (wrong-signer
/// tests).
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

// ── Shared in-memory store ────────────────────────────────────────────────────

#[derive(Clone)]
struct CodeRow {
    email: String,
    tenant_id: Option<String>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
struct PendingRow {
    tenant_id: String,
    expires_at: DateTime<Utc>,
}

#[derive(Default)]
struct Data {
    tenants: HashMap<String, Tenant>,
    networks: HashMap<String, Network>,
    daemons: HashMap<String, Daemon>,
    codes: HashMap<String, CodeRow>,
    pending: HashMap<String, PendingRow>,
    code_log: Vec<(String, DateTime<Utc>)>,
}

/// A shared mock backing store. All mock repositories built from one
/// [`MockStore`] read/write the same data, so saga invariants hold across them.
#[derive(Clone)]
pub struct MockStore(Arc<Mutex<Data>>);

impl MockStore {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Data::default())))
    }

    /// Seed a tenant directly.
    pub fn seed_tenant(&self, tenant: Tenant) {
        self.0
            .lock()
            .unwrap()
            .tenants
            .insert(tenant.id.clone(), tenant);
    }

    /// Number of networks currently stored.
    #[must_use]
    pub fn network_count(&self) -> usize {
        self.0.lock().unwrap().networks.len()
    }

    /// Number of daemons currently stored.
    #[must_use]
    pub fn daemon_count(&self) -> usize {
        self.0.lock().unwrap().daemons.len()
    }

    /// The state of the network with `slug`, if present.
    #[must_use]
    pub fn network_state(&self, slug: &str) -> Option<ProvisioningState> {
        self.0
            .lock()
            .unwrap()
            .networks
            .values()
            .find(|n| n.slug == slug)
            .map(|n| n.provisioning_state)
    }
}

impl Default for MockStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Mock repositories ─────────────────────────────────────────────────────────

#[async_trait]
impl TenantRepository for MockStore {
    async fn create(&self, tenant: &Tenant) -> anyhow::Result<CreateTenantOutcome> {
        let mut d = self.0.lock().unwrap();
        if d.tenants.values().any(|t| t.email == tenant.email) {
            return Ok(CreateTenantOutcome::EmailTaken);
        }
        d.tenants.insert(tenant.id.clone(), tenant.clone());
        Ok(CreateTenantOutcome::Created)
    }

    async fn find_by_id(&self, id: &str) -> anyhow::Result<Option<Tenant>> {
        Ok(self.0.lock().unwrap().tenants.get(id).cloned())
    }

    async fn find_by_email(&self, email: &str) -> anyhow::Result<Option<Tenant>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .tenants
            .values()
            .find(|t| t.email == email)
            .cloned())
    }

    async fn set_subscription_status(
        &self,
        id: &str,
        status: SubscriptionStatus,
    ) -> anyhow::Result<bool> {
        let mut d = self.0.lock().unwrap();
        if let Some(t) = d.tenants.get_mut(id) {
            t.subscription_status = status;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[async_trait]
impl NetworkRepository for MockStore {
    async fn find_by_id(&self, id: &str) -> anyhow::Result<Option<Network>> {
        Ok(self.0.lock().unwrap().networks.get(id).cloned())
    }

    async fn find_by_slug(&self, slug: &str) -> anyhow::Result<Option<Network>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .networks
            .values()
            .find(|n| n.slug == slug)
            .cloned())
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<Network>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .networks
            .values()
            .filter(|n| n.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn count_by_tenant(&self, tenant_id: &str) -> anyhow::Result<i64> {
        let count = self
            .0
            .lock()
            .unwrap()
            .networks
            .values()
            .filter(|n| n.tenant_id == tenant_id)
            .count();
        Ok(i64::try_from(count).unwrap_or(i64::MAX))
    }

    async fn register_network(
        &self,
        network: &Network,
        daemon: &Daemon,
        max_networks: u32,
        max_daemons: u32,
    ) -> anyhow::Result<RegisterNetworkOutcome> {
        let mut d = self.0.lock().unwrap();
        let net_count = d
            .networks
            .values()
            .filter(|n| n.tenant_id == network.tenant_id)
            .count();
        if net_count >= max_networks as usize {
            return Ok(RegisterNetworkOutcome::NetworkLimit);
        }
        let daemon_count = d
            .daemons
            .values()
            .filter(|x| x.tenant_id == network.tenant_id)
            .count();
        if daemon_count >= max_daemons as usize {
            return Ok(RegisterNetworkOutcome::DaemonLimit);
        }
        if d.networks.values().any(|n| n.slug == network.slug) {
            return Ok(RegisterNetworkOutcome::SlugTaken);
        }
        if d.daemons
            .values()
            .any(|x| x.public_key == daemon.public_key)
        {
            return Ok(RegisterNetworkOutcome::DaemonExists);
        }
        d.networks.insert(network.id.clone(), network.clone());
        d.daemons.insert(daemon.id.clone(), daemon.clone());
        d.pending.remove(&daemon.public_key);
        Ok(RegisterNetworkOutcome::Created)
    }

    async fn list_for_reconcile(
        &self,
        state: ProvisioningState,
        region: &str,
        after_id: Option<&str>,
        limit: i64,
    ) -> anyhow::Result<Vec<Network>> {
        let d = self.0.lock().unwrap();
        let mut out: Vec<Network> = d
            .networks
            .values()
            .filter(|n| n.provisioning_state == state && n.region == region)
            .filter(|n| after_id.is_none_or(|a| n.id.as_str() > a))
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out.truncate(usize::try_from(limit).unwrap_or(0));
        Ok(out)
    }

    async fn mark_active(&self, id: &str) -> anyhow::Result<bool> {
        let mut d = self.0.lock().unwrap();
        if let Some(n) = d.networks.get_mut(id)
            && n.provisioning_state == ProvisioningState::Provisioning
        {
            n.provisioning_state = ProvisioningState::Active;
            return Ok(true);
        }
        Ok(false)
    }

    async fn delete_if_deprovisioning(&self, id: &str) -> anyhow::Result<bool> {
        let mut d = self.0.lock().unwrap();
        if d.networks
            .get(id)
            .is_some_and(|n| n.provisioning_state == ProvisioningState::Deprovisioning)
        {
            d.networks.remove(id);
            return Ok(true);
        }
        Ok(false)
    }

    async fn set_deprovisioning(&self, id: &str) -> anyhow::Result<bool> {
        let mut d = self.0.lock().unwrap();
        if let Some(n) = d.networks.get_mut(id)
            && matches!(
                n.provisioning_state,
                ProvisioningState::Active | ProvisioningState::Provisioning
            )
        {
            n.provisioning_state = ProvisioningState::Deprovisioning;
            return Ok(true);
        }
        Ok(false)
    }

    async fn set_deprovisioning_for_tenant(&self, tenant_id: &str) -> anyhow::Result<u64> {
        let mut d = self.0.lock().unwrap();
        let mut count = 0;
        for n in d.networks.values_mut() {
            if n.tenant_id == tenant_id
                && matches!(
                    n.provisioning_state,
                    ProvisioningState::Active | ProvisioningState::Provisioning
                )
            {
                n.provisioning_state = ProvisioningState::Deprovisioning;
                count += 1;
            }
        }
        Ok(count)
    }
}

#[async_trait]
impl DaemonRepository for MockStore {
    async fn find_by_public_key(&self, public_key: &str) -> anyhow::Result<Option<Daemon>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .daemons
            .values()
            .find(|x| x.public_key == public_key)
            .cloned())
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<Daemon>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .daemons
            .values()
            .filter(|x| x.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn list_by_network(&self, network_id: &str) -> anyhow::Result<Vec<Daemon>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .daemons
            .values()
            .filter(|x| x.network_id == network_id)
            .cloned()
            .collect())
    }
}

#[async_trait]
impl EnrollmentRepository for MockStore {
    async fn issue_code(
        &self,
        code_hash: &str,
        email: &str,
        tenant_id: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        self.0.lock().unwrap().codes.insert(
            code_hash.to_string(),
            CodeRow {
                email: email.to_string(),
                tenant_id: tenant_id.map(str::to_string),
                expires_at,
                used_at: None,
            },
        );
        Ok(())
    }

    async fn enroll(
        &self,
        code_hash: &str,
        public_key: &str,
        new_tenant_id: &str,
        default_entitlement: Entitlement,
        now: DateTime<Utc>,
        pending_ttl_secs: i64,
    ) -> anyhow::Result<EnrollOutcome> {
        let mut d = self.0.lock().unwrap();

        // Validate + burn the code.
        let Some(code) = d.codes.get_mut(code_hash) else {
            return Ok(EnrollOutcome::BadCode);
        };
        if code.used_at.is_some() || code.expires_at <= now {
            return Ok(EnrollOutcome::BadCode);
        }
        code.used_at = Some(now);
        let email = code.email.clone();
        let code_tenant_id = code.tenant_id.clone();

        // Resolve the tenant.
        let tenant_id = if let Some(tid) = code_tenant_id {
            tid
        } else if let Some(t) = d.tenants.values().find(|t| t.email == email) {
            t.id.clone()
        } else {
            let tenant = Tenant {
                id: new_tenant_id.to_string(),
                email,
                entitlement: default_entitlement,
                subscription_status: SubscriptionStatus::Active,
                subscription_id: None,
                created_at: now,
            };
            d.tenants.insert(tenant.id.clone(), tenant);
            new_tenant_id.to_string()
        };

        // Enforce the daemon limit.
        let max_daemons = d
            .tenants
            .get(&tenant_id)
            .map_or(0, |t| t.entitlement.max_daemons);
        let daemon_count = d
            .daemons
            .values()
            .filter(|x| x.tenant_id == tenant_id)
            .count();
        if daemon_count >= max_daemons as usize {
            return Ok(EnrollOutcome::DaemonLimit);
        }

        d.pending.insert(
            public_key.to_string(),
            PendingRow {
                tenant_id: tenant_id.clone(),
                expires_at: now + Duration::seconds(pending_ttl_secs),
            },
        );
        Ok(EnrollOutcome::Enrolled { tenant_id })
    }

    async fn find_pending_tenant(
        &self,
        public_key: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .pending
            .get(public_key)
            .filter(|p| p.expires_at > now)
            .map(|p| p.tenant_id.clone()))
    }

    async fn count_code_requests_from_ip(
        &self,
        remote_ip: &str,
        since: DateTime<Utc>,
    ) -> anyhow::Result<i64> {
        let count = self
            .0
            .lock()
            .unwrap()
            .code_log
            .iter()
            .filter(|(ip, at)| ip == remote_ip && *at > since)
            .count();
        Ok(i64::try_from(count).unwrap_or(i64::MAX))
    }

    async fn log_code_request(
        &self,
        remote_ip: &str,
        created_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        self.0
            .lock()
            .unwrap()
            .code_log
            .push((remote_ip.to_string(), created_at));
        Ok(())
    }
}

// ── Builders ──────────────────────────────────────────────────────────────────

/// A throwaway [`Config`] (no real listeners/PEM are opened in mock-backed tests).
#[must_use]
pub fn test_config() -> Config {
    Config {
        global_database_url: "postgres://ignored".to_string(),
        region: "test".to_string(),
        api_listen_addr: "127.0.0.1:0".to_string(),
        mesh_listen_addr: "127.0.0.1:0".to_string(),
        mesh_ca_path: "/dev/null".to_string(),
        mesh_cert_path: "/dev/null".to_string(),
        mesh_key_path: "/dev/null".to_string(),
    }
}

/// A `Signer` over the seed keypair — lets tests mint JWTs the built [`AppState`]'s
/// verifier accepts.
#[must_use]
pub fn test_signer(seed: u8) -> Signer {
    Signer::from_pem(jwt_keypair_pem(seed).0.as_bytes(), None).unwrap()
}

/// Build an [`AppState`] backed by a fresh [`MockStore`], plus the store handle for
/// assertions. The service signer and the state verifier share `seed`'s keypair.
#[must_use]
pub fn build_state(seed: u8) -> (AppState, MockStore) {
    let store = MockStore::new();
    let signer = test_signer(seed);
    let verifier = Verifier::from_pem(jwt_keypair_pem(seed).1.as_bytes()).unwrap();
    let service = Arc::new(TenantsService::new(
        Arc::new(store.clone()),
        Arc::new(store.clone()),
        Arc::new(store.clone()),
        Arc::new(store.clone()),
        signer,
    ));
    let state = AppState::new(test_config(), service, verifier);
    (state, store)
}
