//! `TenantsService` — the global authority's business rules over the
//! tenant/network/daemon model: signup-code issuance, the daemon enroll saga,
//! JWT minting (key-`PoP` authenticated in the handler), network registration with
//! entitlement enforcement, and the mesh reconcile transitions consumed by the
//! regional DDNS provisioner/reaper.
//!
//! The **license** is a separate aggregate: this service never touches the
//! subscription repository or the `subscriptions` crate. It *reads* entitlement
//! through the [`SubscriptionReader`] port (an `Arc<dyn …>` injected by the
//! composition root), and drives subscription side-effects by **publishing domain
//! events** (a reactor reacts). Conversely the network-deprovision side-effect of a
//! deactivated subscription is [`deprovision_networks_for`](Self::deprovision_networks_for),
//! invoked by the network reactor.
//!
//! [`SubscriptionReader`]: wardnet_common::ports::SubscriptionReader

use std::sync::Arc;

use chrono::{Duration, Utc};
use uuid::Uuid;

use wardnet_common::event::{DomainEvent, EventBus};
use wardnet_common::ports::SubscriptionReader;
use wardnet_common::token::{ClaimsSpec, PrincipalType, Signer};
use wardnet_common::validation::{is_valid_name, validate_public_key};

use crate::email::EmailSender;
use crate::error::TenantsError;
use crate::repository::{
    CreateTenantOutcome, Daemon, DaemonRepository, EnrollOutcome, EnrollmentRepository, Network,
    NetworkRepository, ProvisioningState, RegisterNetworkOutcome, Tenant, TenantRepository,
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
    /// The license aggregate — **read-only** access via the port (`current` /
    /// grace-aware `is_active`). All subscription *writes* happen via events.
    subscriptions: Arc<dyn SubscriptionReader>,
    /// Domain-event sink for cross-aggregate side-effects.
    events: Arc<dyn EventBus>,
    /// Transactional email for enrollment codes (Resend in prod, no-op in dev/test).
    email: Arc<dyn EmailSender>,
    /// Shared signing capability (also held by `IdentitiesService` to mint USER JWTs).
    signer: Arc<Signer>,
    /// The fleet's real regions; a network may only be created in one of these
    /// (otherwise no DDNS provisioner would ever pick it up).
    regions: std::collections::HashSet<String>,
}

impl TenantsService {
    // The service composes four repositories plus the subscription aggregate, the
    // event sink, the JWT signer, and the region set — wiring, not a smell.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        tenants: Arc<dyn TenantRepository>,
        networks: Arc<dyn NetworkRepository>,
        daemons: Arc<dyn DaemonRepository>,
        enrollment: Arc<dyn EnrollmentRepository>,
        subscriptions: Arc<dyn SubscriptionReader>,
        events: Arc<dyn EventBus>,
        email: Arc<dyn EmailSender>,
        signer: Arc<Signer>,
        regions: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            tenants,
            networks,
            daemons,
            enrollment,
            subscriptions,
            events,
            email,
            signer,
            regions: regions.into_iter().collect(),
        }
    }

    /// Publish a domain event **best-effort**: a transport failure is logged and
    /// swallowed, never propagated. Events are the fast path; the periodic reconcile is
    /// the correctness guarantee (ADR-0007/0010), so a dropped publish must not fail an
    /// operation whose DB write already committed. (The in-process bus never errs; this
    /// matters once a durable-broker adapter lands.)
    async fn publish_best_effort(&self, event: DomainEvent) {
        if let Err(e) = self.events.publish(&event).await {
            tracing::error!(error = %e, ?event, "failed to publish domain event; reconcile is the safety net");
        }
    }

    /// Whether enrollment codes are delivered by email (a real provider) — when so,
    /// the API does not echo the code in the response.
    #[must_use]
    pub fn email_delivers(&self) -> bool {
        self.email.delivers()
    }

    // ── Account plane ────────────────────────────────────────────────────────────

    /// Create a tenant (management plane) and signal its trial.
    ///
    /// The tenant is created here; its **trial subscription** is opened by the
    /// subscription reactor reacting to the published `TenantCreated` event (so the
    /// returned view may show no subscription yet — it lands a moment later). The
    /// reconcile loop backfills the trial if the event is ever dropped.
    ///
    /// # Errors
    /// [`TenantsError::BadRequest`] on a malformed email; [`TenantsError::Conflict`]
    /// if the email is already taken.
    pub async fn register_tenant(&self, email: &str) -> Result<Tenant, TenantsError> {
        let email = normalize_email(email)?;
        let tenant = Tenant {
            id: Uuid::new_v4().to_string(),
            email,
            created_at: Utc::now(),
            deregistered_at: None,
        };
        match self.tenants.create(&tenant).await? {
            CreateTenantOutcome::Created => {
                // Best-effort: a publish failure must not fail an account whose row is
                // already committed — the reconcile loop backfills the trial. (Never
                // errs on the in-proc bus; matters once a broker adapter lands.)
                self.publish_best_effort(DomainEvent::TenantCreated {
                    tenant_id: tenant.id.clone(),
                })
                .await;
                Ok(tenant)
            }
            CreateTenantOutcome::EmailTaken => Err(TenantsError::Conflict(
                "a tenant already exists for that email".to_string(),
            )),
        }
    }

    /// Look up a **live** tenant by its (normalized) email — the read edge the
    /// Identities aggregate calls to resolve the verified-email join key (ADR-0009).
    /// A one-way `IdentitiesService → TenantsService` call; `IdentitiesService` never
    /// holds the tenant repository.
    ///
    /// # Errors
    /// [`TenantsError::BadRequest`] on a malformed email;
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn find_tenant_by_email(&self, email: &str) -> Result<Option<Tenant>, TenantsError> {
        let email = normalize_email(email)?;
        Ok(self.tenants.find_by_email(&email).await?)
    }

    /// Whether a tenant exists and is **live** (not deregistered) — the liveness edge
    /// the Identities aggregate calls before creating a session, so a tombstoned tenant
    /// cannot log in (mirroring the `deregistered_at` guard `mint_jwt`/`enroll` apply).
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn tenant_is_live(&self, tenant_id: &str) -> Result<bool, TenantsError> {
        Ok(self
            .tenants
            .find_by_id(tenant_id)
            .await?
            .is_some_and(|t| t.deregistered_at.is_none()))
    }

    /// Validate + burn a one-time signup code, returning the email it proves control
    /// of (`None` if unknown / expired / used). The email-proving gate-1 the Identities
    /// aggregate calls for web password signup/reset (ADR-0009) — a one-way edge that
    /// keeps the `enrollment_codes` table inside the tenant aggregate.
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn consume_signup_code(&self, code: &str) -> Result<Option<String>, TenantsError> {
        Ok(self
            .enrollment
            .consume_signup_code(&hash_code(code), Utc::now())
            .await?)
    }

    /// Deprovision all of a tenant's `{active, provisioning}` networks (the DDNS
    /// reaper then tears down DNS and the rows). Invoked by the **network reactor**
    /// on `SubscriptionDeactivated`, and by the reconcile safety net. Idempotent.
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn deprovision_networks_for(&self, tenant_id: &str) -> Result<(), TenantsError> {
        let n = self
            .networks
            .set_deprovisioning_for_tenant(tenant_id)
            .await?;
        if n > 0 {
            tracing::info!(tenant_id, networks = n, "deprovisioning tenant networks");
        }
        Ok(())
    }

    /// Deregister (tombstone) a tenant account: stamp `deregistered_at` and publish
    /// `TenantDeregistered` so the subscription reactor cancels its subscription
    /// (which in turn deprovisions its networks via the network reactor). The
    /// tombstone is terminal; it frees the email for a fresh signup and makes
    /// `mint_jwt`/`enroll` reject the tenant. Idempotent — a second call on an
    /// already-tombstoned tenant is a no-op. Returns `true` if it newly tombstoned.
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
        self.publish_best_effort(DomainEvent::TenantDeregistered {
            tenant_id: tenant_id.to_string(),
        })
        .await;
        tracing::info!(
            tenant_id,
            "tenant deregistered; subscription cancel signalled"
        );
        Ok(true)
    }

    /// All **live** (non-tombstoned) tenant ids — the input the composition root's
    /// reconcile loop iterates (it spans the tenant *and* license aggregates, so it
    /// lives at the composition root, not here — ADR-0010).
    ///
    /// # Errors
    /// [`TenantsError::Internal`] on a repository failure.
    pub async fn list_live_tenant_ids(&self) -> Result<Vec<String>, TenantsError> {
        Ok(self.tenants.list_live_ids().await?)
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

    /// Fetch a tenant by id. The current subscription (a foreign aggregate) is read
    /// separately by the caller via the [`SubscriptionReader`] port and composed into
    /// the view — this service never touches the subscription aggregate.
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

    /// Issue a new-signup one-time code for `email` (public, rate-limited) and email
    /// it. Returns the raw code; the API echoes it only when no real email was sent
    /// (dev) — see [`email_delivers`](Self::email_delivers).
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
        self.email
            .send_enrollment_code(&email, &code)
            .await
            .map_err(TenantsError::Internal)?;
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
        self.email
            .send_enrollment_code(&tenant.email, &code)
            .await
            .map_err(TenantsError::Internal)?;
        Ok(code)
    }

    /// Enroll a daemon: validate + burn the code, create/resolve the tenant, write
    /// the TTL'd pending binding. Returns the tenant the daemon is bound to. When the
    /// enroll **created** the tenant (a new signup), publishes `TenantCreated` so the
    /// subscription reactor opens its trial. The `max_daemons` cap is enforced at
    /// register-network, not here.
    ///
    /// # Errors
    /// [`TenantsError::BadRequest`] on a malformed key; [`TenantsError::BadCode`] on
    /// a bad code.
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
                Utc::now(),
                PENDING_TTL_SECS,
            )
            .await?
        {
            EnrollOutcome::Enrolled {
                tenant_id,
                tenant_created,
            } => {
                if tenant_created {
                    self.publish_best_effort(DomainEvent::TenantCreated {
                        tenant_id: tenant_id.clone(),
                    })
                    .await;
                }
                Ok(EnrollResult { tenant_id })
            }
            EnrollOutcome::BadCode => Err(TenantsError::BadCode(
                "enrollment code is invalid, expired, or already used".to_string(),
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

        // Revocation at refresh: a token is never minted for a deregistered tenant or
        // one whose current subscription does not currently entitle it (a lapsed
        // trial / cancelled sub stops fresh credentials immediately, not just once the
        // reaper deletes rows). The subscription is read via the SubscriptionService.
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
        let entitled = self
            .subscriptions
            .is_active(&tenant_id)
            .await
            .map_err(TenantsError::Internal)?;
        if !entitled {
            return Err(TenantsError::Forbidden(
                "tenant subscription is not active".to_string(),
            ));
        }

        // Grant-scope the token (ADR-0008): a tenant-scoped daemon (still enrolling,
        // no network) reaches only `tenants`; a network-scoped daemon additionally
        // reaches the regional data plane (`ddns` + `tunneller`).
        let audience = if network.is_some() {
            vec!["tenants", "ddns", "tunneller"]
        } else {
            vec!["tenants"]
        };
        let spec = ClaimsSpec {
            tenant_id: &tenant_id,
            principal_type: PrincipalType::Daemon,
            subject: public_key,
            network: network.as_deref(),
            cnf_ed25519_b64: Some(public_key),
            audience,
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

        self.tenants
            .find_by_id(tenant_id)
            .await?
            .ok_or_else(|| TenantsError::NotFound("no such tenant".to_string()))?;

        // Entitlement is granted by the current subscription, not the tenant. Reading
        // it via the SubscriptionReader port keeps Tenants off the subscription repo
        // (and off the subscriptions crate).
        let entitlement = self
            .subscriptions
            .current(tenant_id)
            .await
            .map_err(TenantsError::Internal)?
            .ok_or_else(|| {
                TenantsError::Forbidden("tenant has no active subscription".to_string())
            })?
            .entitlement;

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
                entitlement.max_networks,
                entitlement.max_daemons,
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

/// Lowercase + trim an email and apply a minimal shape check (the verified-email join
/// key — see [`crate::util::normalize_email`], shared with the Identities aggregate).
fn normalize_email(email: &str) -> Result<String, TenantsError> {
    crate::util::normalize_email(email).map_err(|m| TenantsError::BadRequest(m.to_string()))
}

/// Generate a random one-time code, returning `(raw_code_hex, sha256_hex)`. Only
/// the hash is persisted; the raw code is shown once.
fn generate_code() -> (String, String) {
    let code = crate::util::random_token();
    let hash = hash_code(&code);
    (code, hash)
}

/// SHA-256 hex of a raw code (the at-rest form).
fn hash_code(code: &str) -> String {
    crate::util::sha256_hex(code)
}
