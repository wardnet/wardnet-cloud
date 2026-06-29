//! Shared integration-test fixtures (mock store + Harness wiring the three
//! aggregates). Per-binary, each test uses a subset, so silence dead-code here.

#![allow(dead_code)]

//! Shared test fixtures for the composition crate: a deterministic JWT keypair, an
//! in-memory mock store that backs **every** aggregate's repositories (so
//! cross-aggregate invariants hold), and a fully-wired [`Harness`] (the three
//! aggregate services + their `common` ports + the [`AppState`]).
//!
//! This module is **not** `#[cfg(test)]`: the integration tests in `tests/` are
//! separate crates and can only see `pub` items (mirroring the old tenants crate's
//! doc-hidden `test_helpers`). It is the only place that names all three aggregate
//! crates' concrete types — exactly the job of the composition root.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;

use wardnet_common::contract::{Entitlement, InvoiceView, PaymentMethodView, SubscriptionStatus};
use wardnet_common::event::{DomainEvent, EventBus, EventStream, InProcessEventBus};
use wardnet_common::ports::{BillingPort, SubscriptionCommands, SubscriptionReader};
use wardnet_common::token::{Signer, Verifier};

use wardnet_billing::BillingService;
use wardnet_billing::gateway::{CheckoutSession, StripeEvent, StripeGateway};
use wardnet_billing::repository::BillingRepository;
use wardnet_subscriptions::{
    Subscription, SubscriptionRepository, SubscriptionService, TrialPolicy,
};

use wardnet_tenants::config::Config;
use wardnet_tenants::email::EmailSender;
use wardnet_tenants::identities::IdentitiesService;
use wardnet_tenants::identities::provider::ExternalIdentityProvider;
use wardnet_tenants::repository::daemon::{Daemon, DaemonRepository};
use wardnet_tenants::repository::enrollment::{EnrollOutcome, EnrollmentRepository};
use wardnet_tenants::repository::identity::{
    InsertIdentityOutcome, TenantIdentity, TenantIdentityRepository,
};
use wardnet_tenants::repository::network::{
    Network, NetworkRepository, ProvisioningState, RegisterNetworkOutcome,
};
use wardnet_tenants::repository::session::{Session, SessionRepository};
use wardnet_tenants::repository::tenant::{CreateTenantOutcome, Tenant, TenantRepository};
use wardnet_tenants::service::TenantsService;
use wardnet_tenants::state::AppState;

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

/// A Billing-owned provider-reference row (the `stripe_*` ids that moved out of the
/// subscription into Billing's `billing_customers` table), keyed by tenant id.
#[derive(Clone, Default)]
struct BillingCustomer {
    customer: Option<String>,
    subscription: Option<String>,
    price: Option<String>,
}

#[derive(Default)]
struct Data {
    tenants: HashMap<String, Tenant>,
    subscriptions: HashMap<String, Subscription>,
    networks: HashMap<String, Network>,
    daemons: HashMap<String, Daemon>,
    codes: HashMap<String, CodeRow>,
    pending: HashMap<String, PendingRow>,
    code_log: Vec<(String, DateTime<Utc>)>,
    /// Billing provider-reference rows (one per tenant).
    billing_customers: HashMap<String, BillingCustomer>,
    /// Billing webhook idempotency ledger.
    processed_stripe_events: HashSet<String>,
    /// Login methods keyed on `(provider, subject)` (mirrors the PK).
    identities: HashMap<(String, String), TenantIdentity>,
    /// Sessions keyed on `token_hash`.
    sessions: HashMap<String, Session>,
}

/// A shared mock backing store. All mock repositories built from one
/// [`MockStore`] read/write the same data, so saga invariants hold across them —
/// including across the now-separate subscription + billing aggregates.
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

    /// Seed a subscription directly (e.g. an active paid sub with a custom entitlement).
    pub fn seed_subscription(&self, sub: Subscription) {
        self.0
            .lock()
            .unwrap()
            .subscriptions
            .insert(sub.id.clone(), sub);
    }

    /// The tenant's current (non-canceled) subscription, if any.
    #[must_use]
    pub fn current_subscription(&self, tenant_id: &str) -> Option<Subscription> {
        self.0
            .lock()
            .unwrap()
            .subscriptions
            .values()
            .find(|s| s.tenant_id == tenant_id && s.status != SubscriptionStatus::Canceled)
            .cloned()
    }

    /// Number of subscription rows stored for a tenant (history included).
    #[must_use]
    pub fn subscription_count(&self, tenant_id: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .subscriptions
            .values()
            .filter(|s| s.tenant_id == tenant_id)
            .count()
    }

    /// The tenant a recorded provider subscription id maps to (the `billing_customers`
    /// webhook→tenant lookup), if any. `None` means no provider ref was recorded for
    /// that subscription — e.g. a declined (no-metadata) subscription must stay `None`.
    #[must_use]
    pub fn billing_tenant_for_subscription(&self, subscription_id: &str) -> Option<String> {
        self.0
            .lock()
            .unwrap()
            .billing_customers
            .iter()
            .find(|(_, c)| c.subscription.as_deref() == Some(subscription_id))
            .map(|(tenant_id, _)| tenant_id.clone())
    }

    /// Seed a provider customer id for a tenant (so `customer_id` resolves it — e.g. a
    /// tenant that has reached Checkout and has a Stripe customer on file).
    pub fn seed_billing_customer(&self, tenant_id: &str, customer_id: &str) {
        self.0
            .lock()
            .unwrap()
            .billing_customers
            .entry(tenant_id.to_string())
            .or_default()
            .customer = Some(customer_id.to_string());
    }

    /// The provider customer id recorded for a tenant, if any.
    #[must_use]
    pub fn billing_customer_id(&self, tenant_id: &str) -> Option<String> {
        self.0
            .lock()
            .unwrap()
            .billing_customers
            .get(tenant_id)
            .and_then(|c| c.customer.clone())
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

    /// The id of the network with `slug`, if present.
    #[must_use]
    pub fn network_id(&self, slug: &str) -> Option<String> {
        self.0
            .lock()
            .unwrap()
            .networks
            .values()
            .find(|n| n.slug == slug)
            .map(|n| n.id.clone())
    }

    /// The tenant row with `id`, if present (including tombstoned tenants).
    #[must_use]
    pub fn find_tenant(&self, id: &str) -> Option<Tenant> {
        self.0.lock().unwrap().tenants.get(id).cloned()
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
        // Mirror the partial unique index: only LIVE tenants reserve their email.
        if d.tenants
            .values()
            .any(|t| t.email == tenant.email && t.deregistered_at.is_none())
        {
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
            .find(|t| t.email == email && t.deregistered_at.is_none())
            .cloned())
    }

    async fn list_live_ids(&self) -> anyhow::Result<Vec<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .tenants
            .values()
            .filter(|t| t.deregistered_at.is_none())
            .map(|t| t.id.clone())
            .collect())
    }

    async fn set_deregistered(&self, id: &str) -> anyhow::Result<bool> {
        let mut d = self.0.lock().unwrap();
        match d.tenants.get_mut(id) {
            Some(t) if t.deregistered_at.is_none() => {
                t.deregistered_at = Some(chrono::Utc::now());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn delete_tombstoned_empty(&self) -> anyhow::Result<u64> {
        let mut d = self.0.lock().unwrap();
        let to_delete: Vec<String> = d
            .tenants
            .values()
            .filter(|t| t.deregistered_at.is_some())
            .filter(|t| !d.networks.values().any(|n| n.tenant_id == t.id))
            .map(|t| t.id.clone())
            .collect();
        for id in &to_delete {
            d.tenants.remove(id);
            d.daemons.retain(|_, dm| &dm.tenant_id != id);
            d.codes
                .retain(|_, c| c.tenant_id.as_deref() != Some(id.as_str()));
            d.pending.retain(|_, p| &p.tenant_id != id);
        }
        Ok(to_delete.len() as u64)
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
        now: DateTime<Utc>,
        pending_ttl_secs: i64,
    ) -> anyhow::Result<EnrollOutcome> {
        let mut d = self.0.lock().unwrap();

        // Validate the code without burning until the tenant resolves.
        let Some(code) = d.codes.get(code_hash) else {
            return Ok(EnrollOutcome::BadCode);
        };
        if code.used_at.is_some() || code.expires_at <= now {
            return Ok(EnrollOutcome::BadCode);
        }
        let email = code.email.clone();
        let code_tenant_id = code.tenant_id.clone();

        // Resolve the tenant; the saga does not touch subscriptions or enforce limits.
        let (tenant_id, tenant_created) = if let Some(tid) = code_tenant_id {
            // Add-daemon — never into a deregistered tenant.
            match d.tenants.get(&tid) {
                Some(t) if t.deregistered_at.is_none() => (tid, false),
                _ => return Ok(EnrollOutcome::BadCode),
            }
        } else if let Some(t) = d
            .tenants
            .values()
            .find(|t| t.email == email && t.deregistered_at.is_none())
        {
            (t.id.clone(), false)
        } else {
            let tenant = Tenant {
                id: new_tenant_id.to_string(),
                email,
                created_at: now,
                deregistered_at: None,
            };
            d.tenants.insert(tenant.id.clone(), tenant);
            (new_tenant_id.to_string(), true)
        };

        // Burn the code and write the pending binding.
        if let Some(code) = d.codes.get_mut(code_hash) {
            code.used_at = Some(now);
        }
        d.pending.insert(
            public_key.to_string(),
            PendingRow {
                tenant_id: tenant_id.clone(),
                expires_at: now + Duration::seconds(pending_ttl_secs),
            },
        );
        Ok(EnrollOutcome::Enrolled {
            tenant_id,
            tenant_created,
        })
    }

    async fn consume_signup_code(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<String>> {
        let mut d = self.0.lock().unwrap();
        let Some(code) = d.codes.get_mut(code_hash) else {
            return Ok(None);
        };
        // Signup codes only (tenant_id None), unused and unexpired.
        if code.used_at.is_some() || code.expires_at <= now || code.tenant_id.is_some() {
            return Ok(None);
        }
        code.used_at = Some(now);
        Ok(Some(code.email.clone()))
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

#[async_trait]
impl TenantIdentityRepository for MockStore {
    async fn find_by_provider_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> anyhow::Result<Option<TenantIdentity>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .identities
            .get(&(provider.to_string(), subject.to_string()))
            .cloned())
    }

    async fn insert(&self, identity: &TenantIdentity) -> anyhow::Result<InsertIdentityOutcome> {
        let mut d = self.0.lock().unwrap();
        let key = (identity.provider.clone(), identity.subject.clone());
        if d.identities.contains_key(&key) {
            return Ok(InsertIdentityOutcome::AlreadyExists);
        }
        d.identities.insert(key, identity.clone());
        Ok(InsertIdentityOutcome::Created)
    }

    async fn update_secret_hash(
        &self,
        provider: &str,
        subject: &str,
        secret_hash: &str,
    ) -> anyhow::Result<bool> {
        let mut d = self.0.lock().unwrap();
        if let Some(id) = d
            .identities
            .get_mut(&(provider.to_string(), subject.to_string()))
        {
            id.secret_hash = Some(secret_hash.to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn delete_for_tenant(&self, tenant_id: &str) -> anyhow::Result<u64> {
        let mut d = self.0.lock().unwrap();
        let before = d.identities.len();
        d.identities.retain(|_, id| id.tenant_id != tenant_id);
        Ok((before - d.identities.len()) as u64)
    }
}

#[async_trait]
impl SessionRepository for MockStore {
    async fn create(&self, session: &Session) -> anyhow::Result<()> {
        self.0
            .lock()
            .unwrap()
            .sessions
            .insert(session.token_hash.clone(), session.clone());
        Ok(())
    }

    async fn touch_and_get_tenant(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
        new_expires_at: DateTime<Utc>,
    ) -> anyhow::Result<Option<String>> {
        let mut d = self.0.lock().unwrap();
        // Mirror the SQL guard: only a live session belonging to a live (non-tombstoned)
        // tenant resolves.
        let live_tenant = |d: &Data, tid: &str| {
            d.tenants
                .get(tid)
                .is_some_and(|t| t.deregistered_at.is_none())
        };
        let tenant_id = match d.sessions.get(token_hash) {
            Some(s) if s.expires_at > now && live_tenant(&d, &s.tenant_id) => s.tenant_id.clone(),
            _ => return Ok(None),
        };
        d.sessions.get_mut(token_hash).unwrap().expires_at = new_expires_at;
        Ok(Some(tenant_id))
    }

    async fn delete(&self, token_hash: &str) -> anyhow::Result<bool> {
        Ok(self.0.lock().unwrap().sessions.remove(token_hash).is_some())
    }

    async fn delete_for_tenant(&self, tenant_id: &str) -> anyhow::Result<u64> {
        let mut d = self.0.lock().unwrap();
        let before = d.sessions.len();
        d.sessions.retain(|_, s| s.tenant_id != tenant_id);
        Ok((before - d.sessions.len()) as u64)
    }
}

#[async_trait]
impl SubscriptionRepository for MockStore {
    async fn create_trial(&self, sub: &Subscription) -> anyhow::Result<bool> {
        let mut d = self.0.lock().unwrap();
        // Only when the tenant has NO subscription history (mirrors the SQL guard).
        if d.subscriptions
            .values()
            .any(|s| s.tenant_id == sub.tenant_id)
        {
            return Ok(false);
        }
        d.subscriptions.insert(sub.id.clone(), sub.clone());
        Ok(true)
    }

    async fn find_current(&self, tenant_id: &str) -> anyhow::Result<Option<Subscription>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .subscriptions
            .values()
            .find(|s| s.tenant_id == tenant_id && s.status != SubscriptionStatus::Canceled)
            .cloned())
    }

    async fn convert_trial_to_paid(
        &self,
        tenant_id: &str,
        paid: &Subscription,
    ) -> anyhow::Result<()> {
        let mut d = self.0.lock().unwrap();
        for s in d.subscriptions.values_mut() {
            if s.tenant_id == tenant_id && s.status != SubscriptionStatus::Canceled {
                s.status = SubscriptionStatus::Canceled;
            }
        }
        d.subscriptions.insert(paid.id.clone(), paid.clone());
        Ok(())
    }

    async fn update_current(
        &self,
        tenant_id: &str,
        status: SubscriptionStatus,
        entitlement: Entitlement,
        current_period_end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<bool> {
        let mut d = self.0.lock().unwrap();
        if let Some(s) = d
            .subscriptions
            .values_mut()
            .find(|s| s.tenant_id == tenant_id && s.status != SubscriptionStatus::Canceled)
        {
            s.status = status;
            s.entitlement = entitlement;
            s.current_period_end = current_period_end;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn mark_past_due_current(&self, tenant_id: &str) -> anyhow::Result<bool> {
        let mut d = self.0.lock().unwrap();
        if let Some(s) = d
            .subscriptions
            .values_mut()
            .find(|s| s.tenant_id == tenant_id && s.status != SubscriptionStatus::Canceled)
        {
            s.status = SubscriptionStatus::PastDue;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn cancel_current(&self, tenant_id: &str) -> anyhow::Result<bool> {
        let mut d = self.0.lock().unwrap();
        if let Some(s) = d
            .subscriptions
            .values_mut()
            .find(|s| s.tenant_id == tenant_id && s.status != SubscriptionStatus::Canceled)
        {
            s.status = SubscriptionStatus::Canceled;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn list_overdue(
        &self,
        trial_cutoff: DateTime<Utc>,
        payment_cutoff: DateTime<Utc>,
    ) -> anyhow::Result<Vec<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .subscriptions
            .values()
            .filter(|s| match s.status {
                SubscriptionStatus::Trialing => {
                    s.trial_expires_at.is_some_and(|t| t < trial_cutoff)
                }
                SubscriptionStatus::PastDue => {
                    s.current_period_end.is_some_and(|c| c < payment_cutoff)
                }
                _ => false,
            })
            .map(|s| s.tenant_id.clone())
            .collect())
    }
}

#[async_trait]
impl BillingRepository for MockStore {
    async fn upsert_customer(
        &self,
        tenant_id: &str,
        stripe_customer_id: &str,
    ) -> anyhow::Result<()> {
        let mut d = self.0.lock().unwrap();
        d.billing_customers
            .entry(tenant_id.to_string())
            .or_default()
            .customer = Some(stripe_customer_id.to_string());
        Ok(())
    }

    async fn upsert_subscription(
        &self,
        tenant_id: &str,
        stripe_customer_id: &str,
        stripe_subscription_id: &str,
        price_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut d = self.0.lock().unwrap();
        let row = d
            .billing_customers
            .entry(tenant_id.to_string())
            .or_default();
        row.customer = Some(stripe_customer_id.to_string());
        row.subscription = Some(stripe_subscription_id.to_string());
        row.price = price_id.map(str::to_string);
        Ok(())
    }

    async fn customer_id(&self, tenant_id: &str) -> anyhow::Result<Option<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .billing_customers
            .get(tenant_id)
            .and_then(|r| r.customer.clone()))
    }

    async fn tenant_for_subscription(
        &self,
        stripe_subscription_id: &str,
    ) -> anyhow::Result<Option<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .billing_customers
            .iter()
            .find(|(_, r)| r.subscription.as_deref() == Some(stripe_subscription_id))
            .map(|(tenant_id, _)| tenant_id.clone()))
    }

    async fn is_event_processed(&self, event_id: &str) -> anyhow::Result<bool> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .processed_stripe_events
            .contains(event_id))
    }

    async fn record_event(&self, event_id: &str, _now: DateTime<Utc>) -> anyhow::Result<()> {
        self.0
            .lock()
            .unwrap()
            .processed_stripe_events
            .insert(event_id.to_string());
        Ok(())
    }
}

// ── Recording event bus ─────────────────────────────────────────────────────────

/// An [`EventBus`] that records every published event (for `published()` assertions)
/// and queues them for the deterministic [`Harness::pump`] — while also forwarding to
/// a real [`InProcessEventBus`] so a test can drive the spawned async reactors if it
/// wants to.
pub struct RecordingEventBus {
    inner: InProcessEventBus,
    log: Mutex<Vec<DomainEvent>>,
    pending: Mutex<VecDeque<DomainEvent>>,
}

impl RecordingEventBus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: InProcessEventBus::new(256),
            log: Mutex::new(Vec::new()),
            pending: Mutex::new(VecDeque::new()),
        }
    }

    /// Every event published so far, in order (for assertions).
    #[must_use]
    pub fn published(&self) -> Vec<DomainEvent> {
        self.log.lock().unwrap().clone()
    }

    /// Drain the not-yet-pumped events.
    fn take_pending(&self) -> Vec<DomainEvent> {
        self.pending.lock().unwrap().drain(..).collect()
    }
}

impl Default for RecordingEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventBus for RecordingEventBus {
    async fn publish(&self, event: &DomainEvent) -> anyhow::Result<()> {
        self.log.lock().unwrap().push(event.clone());
        self.pending.lock().unwrap().push_back(event.clone());
        self.inner.publish(event).await
    }

    async fn subscribe(&self, group: &str) -> anyhow::Result<Box<dyn EventStream>> {
        self.inner.subscribe(group).await
    }
}

// ── Mock Stripe gateway ─────────────────────────────────────────────────────────

/// A recorded `create_checkout_session` call: `(customer_id, email, price_id, tenant_id)`.
pub type CheckoutCall = (Option<String>, String, String, String);

/// A recording [`StripeGateway`] fake: checkout/portal return canned URLs and record
/// their calls; `construct_event` returns a pre-set [`StripeEvent`] (set by the
/// webhook-endpoint test). No real Stripe — the signature crypto is exercised directly
/// in `wardnet_billing::gateway::tests`, not re-tested here.
pub struct MockStripeGateway {
    checkout_url: String,
    portal_url: String,
    checkout_customer_id: Option<String>,
    event: Mutex<Option<StripeEvent>>,
    /// Recorded `create_checkout_session` calls.
    pub checkouts: Mutex<Vec<CheckoutCall>>,
    /// Canned `default_payment_method` result (defaults to `None`).
    payment_method: Mutex<Option<PaymentMethodView>>,
    /// Canned `list_invoices` result (defaults to empty).
    invoices: Mutex<Vec<InvoiceView>>,
}

impl MockStripeGateway {
    #[must_use]
    pub fn new() -> Self {
        Self {
            checkout_url: "https://checkout.stripe.test/session".to_string(),
            portal_url: "https://billing.stripe.test/portal".to_string(),
            checkout_customer_id: None,
            event: Mutex::new(None),
            checkouts: Mutex::new(Vec::new()),
            payment_method: Mutex::new(None),
            invoices: Mutex::new(Vec::new()),
        }
    }

    /// Set the event `construct_event` will return (webhook-endpoint tests).
    pub fn set_event(&self, event: StripeEvent) {
        *self.event.lock().unwrap() = Some(event);
    }

    /// Set the payment method `default_payment_method` will return.
    pub fn set_payment_method(&self, pm: PaymentMethodView) {
        *self.payment_method.lock().unwrap() = Some(pm);
    }

    /// Set the invoices `list_invoices` will return (newest first).
    pub fn set_invoices(&self, invoices: Vec<InvoiceView>) {
        *self.invoices.lock().unwrap() = invoices;
    }
}

impl Default for MockStripeGateway {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StripeGateway for MockStripeGateway {
    async fn create_checkout_session(
        &self,
        customer_id: Option<&str>,
        email: &str,
        price_id: &str,
        tenant_id: &str,
    ) -> anyhow::Result<CheckoutSession> {
        self.checkouts.lock().unwrap().push((
            customer_id.map(str::to_string),
            email.to_string(),
            price_id.to_string(),
            tenant_id.to_string(),
        ));
        Ok(CheckoutSession {
            url: self.checkout_url.clone(),
            customer_id: self.checkout_customer_id.clone(),
        })
    }

    async fn create_billing_portal_session(&self, _customer_id: &str) -> anyhow::Result<String> {
        Ok(self.portal_url.clone())
    }

    fn construct_event(&self, _payload: &[u8], _sig_header: &str) -> anyhow::Result<StripeEvent> {
        self.event
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no canned event set on MockStripeGateway"))
    }

    async fn default_payment_method(
        &self,
        _customer_id: &str,
    ) -> anyhow::Result<Option<PaymentMethodView>> {
        Ok(self.payment_method.lock().unwrap().clone())
    }

    async fn list_invoices(&self, _customer_id: &str) -> anyhow::Result<Vec<InvoiceView>> {
        Ok(self.invoices.lock().unwrap().clone())
    }
}

// ── Recording email sender ──────────────────────────────────────────────────────

/// A recording [`EmailSender`] fake: records every `(to, code)` and reports
/// `delivers() == false` (so the API still echoes the code, keeping mock-backed HTTP
/// tests exercisable). Use [`sent`](Self::sent) to assert an email was sent.
pub struct RecordingEmailSender {
    sent: Mutex<Vec<(String, String)>>,
}

impl RecordingEmailSender {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
        }
    }

    /// Every `(to, code)` sent so far.
    #[must_use]
    pub fn sent(&self) -> Vec<(String, String)> {
        self.sent.lock().unwrap().clone()
    }
}

impl Default for RecordingEmailSender {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EmailSender for RecordingEmailSender {
    async fn send_enrollment_code(&self, to: &str, code: &str) -> anyhow::Result<()> {
        self.sent
            .lock()
            .unwrap()
            .push((to.to_string(), code.to_string()));
        Ok(())
    }

    fn delivers(&self) -> bool {
        false
    }
}

// ── Builders ──────────────────────────────────────────────────────────────────

/// A throwaway [`Config`] (no real listeners/PEM are opened in mock-backed tests).
#[must_use]
pub fn test_config() -> Config {
    Config {
        global_database_url: "postgres://ignored".to_string(),
        region: "test".to_string(),
        known_regions: vec!["use1".to_string(), "eu1".to_string()],
        api_listen_addr: "127.0.0.1:0".to_string(),
        mesh_listen_addr: "127.0.0.1:0".to_string(),
        trust_bundle_path: "/dev/null".to_string(),
        leaf_cert_path: "/dev/null".to_string(),
        leaf_key_path: "/dev/null".to_string(),
        sweep_interval_secs: 3600,
        trial_days: 60,
        trial_grace_days: 15,
        payment_grace_days: 15,
        sub_reaper_interval_secs: 3600,
        stripe_secret_key: "sk_test_dummy".to_string(),
        stripe_webhook_secret: "whsec_dummy".to_string(),
        account_base_url: "https://account.wardnet.test".to_string(),
        resend_api_key: None,
        email_from: "wardnet <noreply@wardnet.test>".to_string(),
        cookie_key: "test-cookie-key-at-least-sixty-four-bytes-of-entropy-for-the-jar!!"
            .to_string(),
        user_jwt_ttl_secs: 300,
        oauth_redirect_base: "https://account.wardnet.test".to_string(),
        google_client_id: None,
        google_client_secret: None,
        github_client_id: None,
        github_client_secret: None,
    }
}

/// A `Signer` over the seed keypair — lets tests mint JWTs the built [`AppState`]'s
/// verifier accepts.
#[must_use]
pub fn test_signer(seed: u8) -> Signer {
    Signer::from_pem(jwt_keypair_pem(seed).0.as_bytes(), None).unwrap()
}

/// A fully-wired test context over a shared [`MockStore`]: the [`AppState`] plus the
/// service + event handles needed to drive the event-driven flows deterministically.
pub struct Harness {
    pub state: AppState,
    pub store: MockStore,
    pub events: Arc<RecordingEventBus>,
    pub stripe: Arc<MockStripeGateway>,
    pub email: Arc<RecordingEmailSender>,
    pub subscriptions: Arc<SubscriptionService>,
    pub tenants: Arc<TenantsService>,
    pub identities: Arc<IdentitiesService>,
}

impl Harness {
    /// Apply every queued domain event through the reactor handlers, to a fixpoint.
    pub async fn pump(&self) {
        pump_events(
            &self.events,
            &self.subscriptions,
            &self.tenants,
            &self.identities,
        )
        .await;
    }
}

/// Apply every queued domain event through the split reactors, to a fixpoint (a cancel
/// publishes a further `SubscriptionDeactivated`, etc.). The synchronous stand-in for
/// the spawned reactors, so tests stay deterministic. Spans all three aggregates'
/// reactors — subscription (open trial / cancel), network (deprovision cascade), and
/// identities (purge on deregister) — shared by the mock-backed [`Harness`] and the
/// Postgres integration harness.
pub async fn pump_events(
    events: &RecordingEventBus,
    subscriptions: &SubscriptionService,
    tenants: &TenantsService,
    identities: &IdentitiesService,
) {
    loop {
        let batch = events.take_pending();
        if batch.is_empty() {
            break;
        }
        for event in &batch {
            wardnet_subscriptions::reactor::apply_to_subscription(subscriptions, event).await;
            wardnet_tenants::reactor::apply_to_network(tenants, event).await;
            wardnet_tenants::identities::reactor::apply_to_identities(identities, event).await;
        }
    }
}

/// Build a full [`Harness`] with no federated providers.
#[must_use]
pub fn build_harness(seed: u8) -> Harness {
    build_harness_with_providers(seed, HashMap::new())
}

/// Build a full [`Harness`], registering the given federated `providers` on the
/// Identities aggregate (e.g. a [`MockIdentityProvider`] for OIDC-callback tests). The
/// service signer and the state verifier share `seed`'s keypair; the trial policy is
/// the default 60/15/15.
#[must_use]
#[allow(clippy::implicit_hasher)] // test helper; the default hasher is the only caller
pub fn build_harness_with_providers(
    seed: u8,
    providers: HashMap<String, Arc<dyn ExternalIdentityProvider>>,
) -> Harness {
    let store = MockStore::new();
    let events: Arc<RecordingEventBus> = Arc::new(RecordingEventBus::new());
    let stripe: Arc<MockStripeGateway> = Arc::new(MockStripeGateway::new());
    let email: Arc<RecordingEmailSender> = Arc::new(RecordingEmailSender::new());
    let signer = Arc::new(test_signer(seed));
    let verifier = Verifier::from_pem(jwt_keypair_pem(seed).1.as_bytes(), "tenants").unwrap();

    // The license aggregate, shared as both its read + command port.
    let subscriptions = Arc::new(SubscriptionService::new(
        Arc::new(store.clone()) as Arc<dyn SubscriptionRepository>,
        Arc::clone(&events) as Arc<dyn EventBus>,
        TrialPolicy {
            trial_days: 60,
            trial_grace_days: 15,
            payment_grace_days: 15,
        },
    ));
    let subscription_reader: Arc<dyn SubscriptionReader> = subscriptions.clone();
    let subscription_commands: Arc<dyn SubscriptionCommands> = subscriptions.clone();

    // The payment aggregate, driving the license aggregate only through the ports.
    let billing: Arc<dyn BillingPort> = Arc::new(BillingService::new(
        Arc::clone(&stripe) as Arc<dyn StripeGateway>,
        Arc::new(store.clone()) as Arc<dyn BillingRepository>,
        Arc::clone(&subscription_reader),
        Arc::clone(&subscription_commands),
    ));

    let tenants = Arc::new(TenantsService::new(
        Arc::new(store.clone()) as Arc<dyn TenantRepository>,
        Arc::new(store.clone()) as Arc<dyn NetworkRepository>,
        Arc::new(store.clone()) as Arc<dyn DaemonRepository>,
        Arc::new(store.clone()) as Arc<dyn EnrollmentRepository>,
        Arc::clone(&subscription_reader),
        Arc::clone(&events) as Arc<dyn EventBus>,
        Arc::clone(&email) as Arc<dyn EmailSender>,
        Arc::clone(&signer),
        ["use1".to_string(), "eu1".to_string()],
    ));
    let identities = Arc::new(IdentitiesService::new(
        Arc::new(store.clone()) as Arc<dyn TenantIdentityRepository>,
        Arc::new(store.clone()) as Arc<dyn SessionRepository>,
        tenants.clone(),
        providers,
        signer,
        300,
    ));
    let state = AppState::new(
        test_config(),
        tenants.clone(),
        Arc::clone(&subscription_reader),
        Arc::clone(&subscription_commands),
        Arc::clone(&billing),
        identities.clone(),
        verifier,
    );
    Harness {
        state,
        store,
        events,
        stripe,
        email,
        subscriptions,
        tenants,
        identities,
    }
}

/// A mock [`ExternalIdentityProvider`] returning a preset `VerifiedIdentity` from
/// `exchange` (and a fixed authorize URL) — drives the OIDC-callback tests without a
/// real provider.
pub struct MockIdentityProvider {
    identity: wardnet_tenants::identities::provider::VerifiedIdentity,
}

impl MockIdentityProvider {
    #[must_use]
    pub fn new(identity: wardnet_tenants::identities::provider::VerifiedIdentity) -> Self {
        Self { identity }
    }
}

#[async_trait]
impl ExternalIdentityProvider for MockIdentityProvider {
    fn authorize_url(&self) -> wardnet_tenants::identities::provider::AuthorizeRequest {
        wardnet_tenants::identities::provider::AuthorizeRequest {
            url: "https://provider.test/authorize".to_string(),
            csrf_state: "test-state".to_string(),
            verifier: String::new(),
        }
    }

    async fn exchange(
        &self,
        _code: &str,
        _verifier: &str,
    ) -> anyhow::Result<wardnet_tenants::identities::provider::VerifiedIdentity> {
        Ok(self.identity.clone())
    }
}

/// Convenience for tests that only need the [`AppState`] + store (no event pumping).
#[must_use]
pub fn build_state(seed: u8) -> (AppState, MockStore) {
    let h = build_harness(seed);
    (h.state, h.store)
}
