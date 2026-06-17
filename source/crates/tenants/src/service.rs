//! `TenantsService` — the global authority's business rules over the
//! tenant/network/daemon model: signup-code issuance, the daemon enroll saga,
//! JWT minting (key-`PoP` authenticated in the handler), network registration with
//! entitlement enforcement, the subscription-cancel cascade, and the mesh
//! reconcile transitions consumed by the regional DDNS provisioner/reaper.

use std::sync::Arc;

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use wardnet_common::token::{ClaimsSpec, PrincipalType, Signer};
use wardnet_common::validation::{is_valid_name, validate_public_key};

use crate::error::TenantsError;
use crate::repository::tenant::{CreateTenantOutcome, Entitlement};
use crate::repository::{
    Daemon, DaemonRepository, EnrollOutcome, EnrollmentRepository, Network, NetworkRepository,
    ProvisioningState, RegisterNetworkOutcome, SubscriptionStatus, Tenant, TenantRepository,
};

/// Identity JWT lifetime (seconds). Offline revocation is bounded by this.
const IDENTITY_JWT_TTL_SECS: i64 = 3600;
/// One-time enrollment code lifetime (seconds).
const CODE_TTL_SECS: i64 = 300;
/// Pending pubkey↔tenant binding lifetime (seconds) — long enough for the wizard
/// to enroll → getJwt → register-network, short enough to self-clean if abandoned.
const PENDING_TTL_SECS: i64 = 900;
/// Per-IP signup-code requests allowed per hour.
const CODE_REQUESTS_PER_IP_PER_HOUR: i64 = 10;

/// Result of a successful enroll — the tenant the daemon is now (pending-)bound to.
#[derive(Debug)]
pub struct EnrollResult {
    pub tenant_id: String,
}

/// The Tenants business-rule layer.
pub struct TenantsService {
    tenants: Arc<dyn TenantRepository>,
    networks: Arc<dyn NetworkRepository>,
    daemons: Arc<dyn DaemonRepository>,
    enrollment: Arc<dyn EnrollmentRepository>,
    signer: Signer,
    /// The fleet's real regions; a network may only be created in one of these
    /// (otherwise no DDNS provisioner would ever pick it up).
    regions: std::collections::HashSet<String>,
}

impl TenantsService {
    #[must_use]
    pub fn new(
        tenants: Arc<dyn TenantRepository>,
        networks: Arc<dyn NetworkRepository>,
        daemons: Arc<dyn DaemonRepository>,
        enrollment: Arc<dyn EnrollmentRepository>,
        signer: Signer,
        regions: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            tenants,
            networks,
            daemons,
            enrollment,
            signer,
            regions: regions.into_iter().collect(),
        }
    }

    // ── Account plane ────────────────────────────────────────────────────────────

    /// Create a tenant (management plane). Entitlement defaults to
    /// [`Entitlement::DEFAULT`] when not supplied.
    ///
    /// # Errors
    /// [`TenantsError::BadRequest`] on a malformed email; [`TenantsError::Conflict`]
    /// if the email is already taken.
    pub async fn register_tenant(
        &self,
        email: &str,
        entitlement: Option<Entitlement>,
    ) -> Result<Tenant, TenantsError> {
        let email = normalize_email(email)?;
        let tenant = Tenant {
            id: Uuid::new_v4().to_string(),
            email,
            entitlement: entitlement.unwrap_or(Entitlement::DEFAULT),
            subscription_status: SubscriptionStatus::Active,
            subscription_id: None,
            created_at: Utc::now(),
            deregistered_at: None,
        };
        match self.tenants.create(&tenant).await? {
            CreateTenantOutcome::Created => Ok(tenant),
            CreateTenantOutcome::EmailTaken => Err(TenantsError::Conflict(
                "a tenant already exists for that email".to_string(),
            )),
        }
    }

    /// Cancel a tenant's subscription and cascade its `{active, provisioning}`
    /// networks to `deprovisioning` (the reaper then tears down DNS).
    ///
    /// # Errors
    /// [`TenantsError::NotFound`] if no such tenant.
    pub async fn cancel_subscription(&self, tenant_id: &str) -> Result<(), TenantsError> {
        if !self
            .tenants
            .set_subscription_status(tenant_id, SubscriptionStatus::Canceled)
            .await?
        {
            return Err(TenantsError::NotFound("no such tenant".to_string()));
        }
        let n = self
            .networks
            .set_deprovisioning_for_tenant(tenant_id)
            .await?;
        tracing::info!(
            tenant_id,
            networks = n,
            "subscription canceled; networks deprovisioning"
        );
        Ok(())
    }

    /// Deregister (tombstone) a tenant account: stamp `deregistered_at`, cascade its
    /// `{active, provisioning}` networks to `deprovisioning` (the DDNS reaper then tears
    /// down DNS and the row), and cancel its subscription. The tombstone is terminal and
    /// distinct from the reversible `subscription_status`; it frees the email for a fresh
    /// signup and makes `mint_jwt`/`enroll` reject the tenant. Idempotent — a second call
    /// on an already-tombstoned tenant is a no-op. Returns `true` if it newly tombstoned.
    ///
    /// # Errors
    /// [`TenantsError::NotFound`] if no such tenant.
    pub async fn deregister_tenant(&self, tenant_id: &str) -> Result<bool, TenantsError> {
        // find_by_id returns tombstoned tenants too, so a missing row is the only 404.
        if self.tenants.find_by_id(tenant_id).await?.is_none() {
            return Err(TenantsError::NotFound("no such tenant".to_string()));
        }
        if !self.tenants.set_deregistered(tenant_id).await? {
            // Already tombstoned — idempotent no-op.
            return Ok(false);
        }
        let n = self
            .networks
            .set_deprovisioning_for_tenant(tenant_id)
            .await?;
        self.tenants
            .set_subscription_status(tenant_id, SubscriptionStatus::Canceled)
            .await?;
        tracing::info!(
            tenant_id,
            networks = n,
            "tenant deregistered; networks deprovisioning, subscription canceled"
        );
        Ok(true)
    }

    /// Delete tombstoned tenants whose networks are fully deprovisioned (FK-cascading
    /// their daemons, codes, and pending enrollments). Driven by a periodic sweep loop;
    /// N-replica-safe and idempotent. Returns the number of tenants deleted.
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn sweep_deregistered(&self) -> Result<u64, TenantsError> {
        let deleted = self.tenants.delete_tombstoned_empty().await?;
        if deleted > 0 {
            tracing::info!(deleted, "swept tombstoned tenants");
        }
        Ok(deleted)
    }

    /// List a tenant's networks.
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn list_networks(&self, tenant_id: &str) -> Result<Vec<Network>, TenantsError> {
        Ok(self.networks.list_by_tenant(tenant_id).await?)
    }

    /// Fetch the full [`Network`] resource by id (the mesh-plane resource read).
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn find_network(&self, network_id: &str) -> Result<Option<Network>, TenantsError> {
        Ok(self.networks.find_by_id(network_id).await?)
    }

    /// Fetch the full [`Tenant`] resource by id (the mesh-plane resource read).
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn find_tenant(&self, tenant_id: &str) -> Result<Option<Tenant>, TenantsError> {
        Ok(self.tenants.find_by_id(tenant_id).await?)
    }

    /// List a tenant's daemons.
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn list_tenant_daemons(&self, tenant_id: &str) -> Result<Vec<Daemon>, TenantsError> {
        Ok(self.daemons.list_by_tenant(tenant_id).await?)
    }

    /// List a network's daemons, scoped to `tenant_id` (a network belonging to a
    /// different tenant reads as not found).
    ///
    /// # Errors
    /// [`TenantsError::NotFound`] if the network is absent or another tenant's.
    pub async fn list_network_daemons(
        &self,
        tenant_id: &str,
        network_id: &str,
    ) -> Result<Vec<Daemon>, TenantsError> {
        let network = self
            .networks
            .find_by_id(network_id)
            .await?
            .filter(|n| n.tenant_id == tenant_id)
            .ok_or_else(|| TenantsError::NotFound("no such network".to_string()))?;
        Ok(self.daemons.list_by_network(&network.id).await?)
    }

    /// Mark a tenant's network for deprovisioning (management "delete network").
    /// Idempotent — already-deprovisioning is a no-op success.
    ///
    /// # Errors
    /// [`TenantsError::NotFound`] if the network is absent or another tenant's.
    pub async fn delete_network(&self, tenant_id: &str, slug: &str) -> Result<(), TenantsError> {
        let network = self
            .networks
            .find_by_slug(slug)
            .await?
            .filter(|n| n.tenant_id == tenant_id)
            .ok_or_else(|| TenantsError::NotFound("no such network".to_string()))?;
        if network.provisioning_state != ProvisioningState::Deprovisioning {
            self.networks.set_deprovisioning(&network.id).await?;
        }
        Ok(())
    }

    // ── Enrollment plane (codes + enroll + JWT) ──────────────────────────────────

    /// Issue a new-signup one-time code for `email` (public, rate-limited). Returns
    /// the raw code (emailed in production; returned to the caller for now).
    ///
    /// # Errors
    /// [`TenantsError::RateLimited`] past the per-IP hourly cap.
    pub async fn issue_signup_code(
        &self,
        email: &str,
        remote_ip: &str,
    ) -> Result<String, TenantsError> {
        let email = normalize_email(email)?;
        let since = Utc::now() - Duration::hours(1);
        if self
            .enrollment
            .count_code_requests_from_ip(remote_ip, since)
            .await?
            >= CODE_REQUESTS_PER_IP_PER_HOUR
        {
            return Err(TenantsError::RateLimited(
                "too many code requests; try again later".to_string(),
            ));
        }
        self.enrollment
            .log_code_request(remote_ip, Utc::now())
            .await?;
        let (code, code_hash) = generate_code();
        self.enrollment
            .issue_code(
                &code_hash,
                &email,
                None,
                Utc::now() + Duration::seconds(CODE_TTL_SECS),
            )
            .await?;
        Ok(code)
    }

    /// Issue an add-daemon one-time code for an existing tenant. Returns the raw code.
    ///
    /// # Errors
    /// [`TenantsError::NotFound`] if the tenant does not exist;
    /// [`TenantsError::Forbidden`] if the tenant is deregistered.
    pub async fn issue_tenant_code(&self, tenant_id: &str) -> Result<String, TenantsError> {
        let tenant = self
            .tenants
            .find_by_id(tenant_id)
            .await?
            .ok_or_else(|| TenantsError::NotFound("no such tenant".to_string()))?;
        // A tombstoned tenant cannot grow daemons (enroll would reject the code anyway —
        // reject here so the issue itself fails cleanly, mirroring `mint_jwt`).
        if tenant.deregistered_at.is_some() {
            return Err(TenantsError::Forbidden(
                "tenant is deregistered".to_string(),
            ));
        }
        let (code, code_hash) = generate_code();
        self.enrollment
            .issue_code(
                &code_hash,
                &tenant.email,
                Some(tenant_id),
                Utc::now() + Duration::seconds(CODE_TTL_SECS),
            )
            .await?;
        Ok(code)
    }

    /// Enroll a daemon: validate + burn the code, create/resolve the tenant, write
    /// the TTL'd pending binding. Returns the tenant the daemon is bound to.
    ///
    /// # Errors
    /// [`TenantsError::BadRequest`] on a malformed key; [`TenantsError::BadCode`] on
    /// a bad code; [`TenantsError::EntitlementExceeded`] at the daemon limit.
    pub async fn enroll(&self, code: &str, public_key: &str) -> Result<EnrollResult, TenantsError> {
        // Validate the key shape up front (the enroll saga stores the string form).
        validate_public_key(public_key)
            .map_err(|_| TenantsError::BadRequest("invalid public_key".to_string()))?;
        let code_hash = hash_code(code);
        match self
            .enrollment
            .enroll(
                &code_hash,
                public_key,
                &Uuid::new_v4().to_string(),
                Entitlement::DEFAULT,
                Utc::now(),
                PENDING_TTL_SECS,
            )
            .await?
        {
            EnrollOutcome::Enrolled { tenant_id } => Ok(EnrollResult { tenant_id }),
            EnrollOutcome::BadCode => Err(TenantsError::BadCode(
                "enrollment code is invalid, expired, or already used".to_string(),
            )),
            EnrollOutcome::DaemonLimit => Err(TenantsError::EntitlementExceeded(
                "tenant has reached its daemon limit".to_string(),
            )),
        }
    }

    /// Mint an identity JWT for the daemon owning `public_key`. The caller has
    /// already verified the key-`PoP` signature. The token is **network-scoped** if
    /// the daemon has registered a network, else **tenant-scoped** (still in
    /// enrollment). `sub` is the public key — the daemon's stable identity.
    ///
    /// # Errors
    /// [`TenantsError::BadCode`] if the key is neither a registered daemon nor a
    /// live pending binding (unknown/expired enrollment).
    pub async fn mint_jwt(&self, public_key: &str) -> Result<String, TenantsError> {
        let now = Utc::now();

        // Resolve scope: a registered daemon is network-scoped; a still-pending
        // daemon is tenant-scoped (no network yet).
        let (tenant_id, network): (String, Option<String>) =
            if let Some(daemon) = self.daemons.find_by_public_key(public_key).await? {
                (daemon.tenant_id, Some(daemon.network_id))
            } else if let Some(tid) = self.enrollment.find_pending_tenant(public_key, now).await? {
                (tid, None)
            } else {
                return Err(TenantsError::BadCode(
                    "no registered daemon or live enrollment for this key".to_string(),
                ));
            };

        // Revocation at refresh: a token is never minted for a tenant whose
        // subscription is not active (a canceled tenant's daemons stop getting
        // fresh credentials immediately, not just once the reaper deletes rows).
        let tenant = self
            .tenants
            .find_by_id(&tenant_id)
            .await?
            .ok_or_else(|| TenantsError::NotFound("tenant not found".to_string()))?;
        if tenant.deregistered_at.is_some() {
            return Err(TenantsError::Forbidden(
                "tenant is deregistered".to_string(),
            ));
        }
        if tenant.subscription_status != SubscriptionStatus::Active {
            return Err(TenantsError::Forbidden(
                "tenant subscription is not active".to_string(),
            ));
        }

        let spec = ClaimsSpec {
            tenant_id: &tenant_id,
            principal_type: PrincipalType::Daemon,
            subject: public_key,
            network: network.as_deref(),
            cnf_ed25519_b64: Some(public_key),
        };
        self.signer
            .sign(&spec, now.timestamp(), IDENTITY_JWT_TTL_SECS)
            .map_err(TenantsError::Internal)
    }

    // ── Daemon plane (availability + register-network) ───────────────────────────

    /// Whether a vanity slug is available: well-formed, not reserved, and not held
    /// by any existing network (in any state).
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn check_availability(&self, slug: &str) -> Result<bool, TenantsError> {
        if !is_valid_name(slug) {
            return Ok(false);
        }
        Ok(self.networks.find_by_slug(slug).await?.is_none())
    }

    /// Register a network for `tenant_id` and bind the calling daemon
    /// (`public_key`) to it — atomic, with `max_networks` / `max_daemons` enforced.
    /// `display_name` defaults to the slug when empty.
    ///
    /// # Errors
    /// [`TenantsError::BadRequest`] on a bad slug/region; [`TenantsError::Conflict`]
    /// on a taken slug or already-registered daemon;
    /// [`TenantsError::EntitlementExceeded`] at a limit;
    /// [`TenantsError::NotFound`] if the tenant has vanished.
    pub async fn register_network(
        &self,
        tenant_id: &str,
        public_key: &str,
        slug: &str,
        display_name: Option<&str>,
        region: &str,
    ) -> Result<Network, TenantsError> {
        if !is_valid_name(slug) {
            return Err(TenantsError::BadRequest(
                "slug must be 3-32 chars of [a-z0-9-], not reserved".to_string(),
            ));
        }
        let region = region.trim();
        // Reject unknown regions: a network in a region no DDNS provisioner serves
        // would be stuck `provisioning` forever while consuming a slug + a slot.
        if !self.regions.contains(region) {
            return Err(TenantsError::BadRequest(format!(
                "unknown region '{region}'"
            )));
        }

        let tenant = self
            .tenants
            .find_by_id(tenant_id)
            .await?
            .ok_or_else(|| TenantsError::NotFound("no such tenant".to_string()))?;

        let now = Utc::now();
        let display_name = display_name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(slug)
            .to_string();
        let network = Network {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            slug: slug.to_string(),
            display_name,
            region: region.to_string(),
            provisioning_state: ProvisioningState::Provisioning,
            created_at: now,
            updated_at: now,
        };
        let daemon = Daemon {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            network_id: network.id.clone(),
            public_key: public_key.to_string(),
            created_at: now,
        };

        match self
            .networks
            .register_network(
                &network,
                &daemon,
                tenant.entitlement.max_networks,
                tenant.entitlement.max_daemons,
            )
            .await?
        {
            RegisterNetworkOutcome::Created => Ok(network),
            RegisterNetworkOutcome::SlugTaken => {
                Err(TenantsError::Conflict(format!("'{slug}' is already taken")))
            }
            RegisterNetworkOutcome::NetworkLimit => Err(TenantsError::EntitlementExceeded(
                "tenant has reached its network limit".to_string(),
            )),
            RegisterNetworkOutcome::DaemonLimit => Err(TenantsError::EntitlementExceeded(
                "tenant has reached its daemon limit".to_string(),
            )),
            RegisterNetworkOutcome::DaemonExists => Err(TenantsError::Conflict(
                "this daemon is already registered".to_string(),
            )),
        }
    }

    // ── Mesh plane (DDNS provisioner / reaper) ───────────────────────────────────

    /// A cursor page of networks in `state` for `region` (ids after `after_id`).
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn reconcile_page(
        &self,
        state: ProvisioningState,
        region: &str,
        after_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<Network>, TenantsError> {
        Ok(self
            .networks
            .list_for_reconcile(state, region, after_id, limit)
            .await?)
    }

    /// The current [`ProvisioningState`] of a network, or `None` if it does not
    /// exist. Lets the mesh transition handler give idempotent answers.
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn network_state(
        &self,
        network_id: &str,
    ) -> Result<Option<ProvisioningState>, TenantsError> {
        Ok(self
            .networks
            .find_by_id(network_id)
            .await?
            .map(|n| n.provisioning_state))
    }

    /// `provisioning → active` (provisioner). Returns whether it applied.
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn mark_network_active(&self, network_id: &str) -> Result<bool, TenantsError> {
        Ok(self.networks.mark_active(network_id).await?)
    }

    /// `deprovisioning →` delete row (reaper). Returns whether it applied.
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn finish_deprovision(&self, network_id: &str) -> Result<bool, TenantsError> {
        Ok(self.networks.delete_if_deprovisioning(network_id).await?)
    }
}

/// Lowercase + trim an email and apply a minimal shape check.
fn normalize_email(email: &str) -> Result<String, TenantsError> {
    let e = email.trim().to_lowercase();
    if e.len() < 3 || !e.contains('@') {
        return Err(TenantsError::BadRequest("invalid email".to_string()));
    }
    Ok(e)
}

/// Generate a random one-time code, returning `(raw_code_hex, sha256_hex)`. Only
/// the hash is persisted; the raw code is shown once.
fn generate_code() -> (String, String) {
    let bytes: [u8; 32] = rand::random();
    let code = hex::encode(bytes);
    let hash = hash_code(&code);
    (code, hash)
}

/// SHA-256 hex of a raw code (the at-rest form).
fn hash_code(code: &str) -> String {
    hex::encode(Sha256::digest(code.as_bytes()))
}

#[cfg(test)]
mod tests;
