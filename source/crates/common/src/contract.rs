//! Shared API contract DTOs — the whole wire surface in one place.
//!
//! Every request/response type that crosses the boundary between a wardnet service
//! and its callers lives here, so a producer-side change is caught at **compile
//! time** on the consumer. This generalizes the [`ErrorBody`](crate::error::ErrorBody)
//! precedent: the producer maps its domain model → the contract DTO; the consumer
//! deserializes the same type. The embedded lifecycle enums ([`ProvisioningState`],
//! [`SubscriptionStatus`]) and the [`Entitlement`] value object live here too, and
//! double as the Tenants DB-domain enums — their `as_str` / `from_db` helpers travel
//! with them so there is one enum, not a domain+wire pair.
//!
//! The `impl From<DomainType> for ContractDTO` conversions stay in the owning
//! service crate (the domain type is local there, so the orphan rule allows it).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Embedded enums / nested value objects ──────────────────────────────────────

/// Network lifecycle. `deprovisioned` is intentionally absent — the reaper's final
/// transition deletes the row (freeing the slug).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProvisioningState {
    /// Created; the DDNS provisioner has not yet published its DNS record.
    Provisioning,
    /// DNS record published; live.
    Active,
    /// Slated for teardown; the reaper deletes its DNS record then the row.
    Deprovisioning,
}

impl ProvisioningState {
    /// The DB/text form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ProvisioningState::Provisioning => "provisioning",
            ProvisioningState::Active => "active",
            ProvisioningState::Deprovisioning => "deprovisioning",
        }
    }

    /// Parse from the DB/text form.
    ///
    /// # Errors
    /// Returns an error on an unrecognized value (a CHECK-constraint violation
    /// upstream would have to have happened first).
    pub fn from_db(s: &str) -> anyhow::Result<Self> {
        match s {
            "provisioning" => Ok(ProvisioningState::Provisioning),
            "active" => Ok(ProvisioningState::Active),
            "deprovisioning" => Ok(ProvisioningState::Deprovisioning),
            other => Err(anyhow::anyhow!("unknown provisioning_state {other:?}")),
        }
    }
}

/// Per-tenant limits. JSONB-stored so new dimensions need no migration; `serde`
/// defaults keep old rows readable as dimensions are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Entitlement {
    /// Maximum networks the tenant may hold.
    #[serde(default = "Entitlement::one")]
    pub max_networks: u32,
    /// Maximum daemons across all the tenant's networks.
    #[serde(default = "Entitlement::one")]
    pub max_daemons: u32,
}

impl Entitlement {
    /// The default a self-service (wizard-enrolled) tenant receives.
    pub const DEFAULT: Entitlement = Entitlement {
        max_networks: 1,
        max_daemons: 1,
    };

    const fn one() -> u32 {
        1
    }
}

impl Default for Entitlement {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Subscription lifecycle. A tenant's **current** subscription is its single
/// non-`Canceled` row; losing it (or its cancel) cascades the tenant's networks to
/// `deprovisioning`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionStatus {
    /// Free trial — no card, no Stripe subscription yet. Entitled until
    /// `trial_expires_at + grace`, after which the reaper cancels it.
    Trialing,
    /// Live paid subscription (Stripe `active`/`trialing`).
    Active,
    /// A payment failed (Stripe `past_due`). Entitled through the payment grace
    /// window (`current_period_end + grace`); the reaper cancels it past that.
    PastDue,
    /// Terminal — no longer the current subscription; its networks are cascaded to
    /// `deprovisioning`.
    Canceled,
}

impl SubscriptionStatus {
    /// The DB/text form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SubscriptionStatus::Trialing => "trialing",
            SubscriptionStatus::Active => "active",
            SubscriptionStatus::PastDue => "past_due",
            SubscriptionStatus::Canceled => "canceled",
        }
    }

    /// Parse from the DB/text form. An unrecognized value maps to `Canceled` — the
    /// **safe-closed** default: an unknown billing state must never grant service.
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "trialing" => SubscriptionStatus::Trialing,
            "active" => SubscriptionStatus::Active,
            "past_due" => SubscriptionStatus::PastDue,
            _ => SubscriptionStatus::Canceled,
        }
    }
}

// ── Resource views (full representations — never trimmed to the caller) ─────────

/// The full **Network** resource. Producer: Tenants (`POST /v1/networks`, the mesh
/// `GET /v1/networks` work-queue + `GET /v1/networks/{id}` resource read).
/// Consumers: the DDNS reconciler and the Tunneller routing policy.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NetworkView {
    pub id: String,
    pub tenant_id: String,
    pub slug: String,
    pub display_name: String,
    pub region: String,
    pub provisioning_state: ProvisioningState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The full **Subscription** resource — the billing aggregate that grants a
/// tenant's [`Entitlement`]. Producer: Tenants (account plane + embedded in
/// [`TenantView`]). A tenant's *current* subscription is its single non-`Canceled`
/// row; `Canceled` rows are history and are never embedded as current.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SubscriptionView {
    pub id: String,
    pub status: SubscriptionStatus,
    /// The limits this subscription's plan grants.
    pub entitlement: Entitlement,
    /// Stripe Customer handle (the tenant's stable billing identity); `None` until
    /// the tenant first reaches checkout.
    pub stripe_customer_id: Option<String>,
    /// Stripe Subscription handle; `None` while still on the card-less trial.
    pub stripe_subscription_id: Option<String>,
    /// The purchased Stripe Price id; `None` on the trial.
    pub price_id: Option<String>,
    /// When the free trial lapses (a `Trialing` subscription only).
    pub trial_expires_at: Option<DateTime<Utc>>,
    /// End of the current paid period (a paid subscription only).
    pub current_period_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SubscriptionView {
    /// Whether this subscription currently entitles the tenant to service.
    ///
    /// A subscription embedded as a tenant's *current* one is, by construction,
    /// non-`Canceled` — the grace windows are enforced producer-side (the reaper
    /// cancels a trial/past-due subscription once its grace lapses, dropping it out
    /// of "current"). So a consumer (e.g. the Tunneller) treats any current
    /// subscription as entitling and a *missing* one as not.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !matches!(self.status, SubscriptionStatus::Canceled)
    }
}

/// The full **Tenant** resource. Producer: Tenants (account plane + the mesh
/// `GET /v1/tenants/{id}` resource read). Consumer: the Tunneller subscription
/// check (reads the embedded current subscription).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TenantView {
    pub id: String,
    pub email: String,
    /// The tenant's current (non-`Canceled`) subscription, or `None` if it has no
    /// live subscription (trial reaped / fully canceled) — i.e. not entitled.
    pub subscription: Option<SubscriptionView>,
    pub created_at: DateTime<Utc>,
}

/// The full **Daemon** resource. Producer: Tenants (account-plane listings).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DaemonView {
    pub id: String,
    pub network_id: String,
    pub public_key: String,
    pub created_at: DateTime<Utc>,
}

// ── Tenants — bootstrap plane ───────────────────────────────────────────────────

/// Request body for `POST /v1/enrollment-codes`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SignupCodeRequest {
    /// The account email a code should be issued for.
    pub email: String,
}

/// Response body for `POST /v1/enrollment-codes`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SignupCodeResponse {
    /// The one-time code. **Transitional:** returned here until email delivery
    /// (Resend) lands; thereafter it is emailed, not returned.
    pub code: String,
}

/// Request body for `POST /v1/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EnrollRequest {
    /// The one-time code (raw value, as emailed to the tenant).
    pub code: String,
    /// Base64-encoded raw Ed25519 public key (32 bytes) the daemon will sign with.
    pub public_key: String,
}

/// Response body for `POST /v1/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EnrollResponse {
    /// The tenant this daemon is now (pending-)bound to.
    pub tenant_id: String,
}

/// Request body for `POST /v1/token`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TokenRequest {
    /// Base64-encoded raw Ed25519 public key (32 bytes) — the enrolled/registered key.
    pub public_key: String,
}

/// Response body for `POST /v1/token`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TokenResponse {
    /// The minted identity JWT (`EdDSA`).
    pub token: String,
}

// ── Tenants — daemon / network plane ────────────────────────────────────────────

/// Query for `GET /v1/availability`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::IntoParams)]
pub struct AvailabilityQuery {
    /// The vanity slug to check.
    pub slug: String,
}

/// Response body for `GET /v1/availability`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AvailabilityResponse {
    /// `true` if the slug is well-formed, not reserved, and unused.
    pub available: bool,
}

/// Request body for `POST /v1/networks`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RegisterNetworkRequest {
    /// Desired vanity slug (`[a-z0-9-]`, 3–32, not reserved).
    pub slug: String,
    /// Human-facing name; defaults to the slug when omitted/empty.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Region that will own this network's DNS/tunnel.
    pub region: String,
}

// ── Tenants — account plane ─────────────────────────────────────────────────────

/// Request body for `POST /v1/tenants`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RegisterTenantRequest {
    pub email: String,
    /// Optional entitlement; defaults to 1 network / 1 daemon.
    #[serde(default)]
    pub entitlement: Option<Entitlement>,
}

/// Response body for the add-daemon code endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CodeResponse {
    /// The one-time code (transitional — emailed in production).
    pub code: String,
}

/// Request body for `PATCH /v1/tenants/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateTenantRequest {
    /// Only `"canceled"` is accepted (cancels the subscription + cascades networks).
    pub subscription_status: String,
}

// ── Tenants — mesh / SERVICE plane (work queue) ─────────────────────────────────

/// Query for the reconcile scan (`GET /v1/networks`, mesh-mTLS plane). The
/// `provisioningState` filter is always a real [`ProvisioningState`]; it is parsed
/// (not typed) here so an invalid value maps to `400` rather than a deserialize
/// rejection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileQuery {
    pub provisioning_state: String,
    pub region: String,
    pub after_id: Option<String>,
    pub limit: Option<i64>,
}

/// Body for a network state transition (`PATCH /v1/networks/{id}`, mesh-mTLS plane).
/// The target is `"active"` (provisioner published DNS) or `"deprovisioned"` (reaper
/// tore it down → delete the row); the latter is *not* a stored
/// [`ProvisioningState`], so this stays a free `String`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransitionRequest {
    pub provisioning_state: String,
}

// ── DDNS — daemon plane ─────────────────────────────────────────────────────────

/// Request body for `PUT /v1/ip`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReportIpRequest {
    /// The daemon's current public IPv4 address, e.g. `"93.184.216.34"`.
    /// Must be a globally routable unicast address (private/reserved/multicast
    /// addresses are rejected with `400`).
    pub ip: String,
}

/// Request body for `PUT /v1/acme-challenge`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SetAcmeChallengeRequest {
    /// The ACME DNS-01 challenge token values (raw, no quoting needed). A
    /// **per-user wildcard certificate** authorizes its apex and wildcard SANs
    /// through the same `_acme-challenge` name, so this carries one value per SAN
    /// (typically two), published as that many TXT records at once.
    pub values: Vec<String>,
}
