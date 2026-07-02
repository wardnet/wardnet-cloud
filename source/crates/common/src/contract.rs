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

/// The flow a one-time [verification code](VerificationCodeRequest) is bound to
/// (PR3). A code issued for one purpose can never be consumed by another, closing
/// cross-purpose replay. Doubles as the `enrollment_codes.purpose` DB value (the
/// [`ProvisioningState`] pattern). `enrollment` covers both daemon paths (new-signup
/// and add-daemon), which the orthogonal `tenant_id` column already distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodePurpose {
    /// Web password signup (`POST /v1/auth/password/signup`).
    Signup,
    /// Web password reset — **unauthenticated** recovery (`POST /v1/auth/password/reset`).
    PasswordReset,
    /// Web password set/change by an **authenticated** user (`POST /v1/me/password`).
    /// Separate purpose from [`Self::PasswordReset`] so a recovery code can never be
    /// consumed by the authenticated change flow (and vice-versa), and so its email
    /// copy / limits can evolve independently.
    PasswordChange,
    /// Daemon enrollment (`POST /v1/enroll`).
    Enrollment,
}

impl CodePurpose {
    /// The DB/text form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CodePurpose::Signup => "signup",
            CodePurpose::PasswordReset => "password_reset",
            CodePurpose::PasswordChange => "password_change",
            CodePurpose::Enrollment => "enrollment",
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

/// The full **Subscription** resource — the **license** aggregate that grants a
/// tenant's [`Entitlement`]. Provider-agnostic: payment-provider reference ids
/// (Stripe customer/subscription/price) live in the **Billing** aggregate and are
/// surfaced by Billing's own read endpoints, not here. Producer: Tenants (account
/// plane + embedded in [`TenantView`]). A tenant's *current* subscription is its
/// single non-`Canceled` row; `Canceled` rows are history and are never embedded as
/// current.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SubscriptionView {
    pub id: String,
    pub status: SubscriptionStatus,
    /// The limits this subscription's plan grants.
    pub entitlement: Entitlement,
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

/// Request body for `POST /v1/verification-codes` — the unified, `RESTful` one-time
/// code resource (PR3). `purpose` binds the issued code so it can only be consumed
/// by the matching flow.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VerificationCodeRequest {
    /// The account email a code should be issued for.
    pub email: String,
    /// What the code may be exchanged for (`signup` / `password_reset` / `enrollment`).
    pub purpose: CodePurpose,
}

/// Response body for `POST /v1/verification-codes`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VerificationCodeResponse {
    /// The one-time code — `None` once it has been **emailed** (production), `Some`
    /// only in the dev/no-op email path so the flow stays exercisable without a mailbox.
    pub code: Option<String>,
}

/// One connected login method for `GET /v1/me/identities`. Deliberately omits the
/// stored secret (invariant #1): never carries a password hash or provider subject.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConnectedIdentityView {
    /// The login-method provider (`password` / `google` / `github`).
    pub provider: String,
    /// A human-facing label — the provider-verified email.
    pub label: String,
    /// When this method was linked to the account.
    pub connected_at: DateTime<Utc>,
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

/// Response body for the add-daemon code endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CodeResponse {
    /// The one-time code — `None` once emailed (production), `Some` in the dev/no-op
    /// email path.
    pub code: Option<String>,
}

/// Request body for `PATCH /v1/tenants/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateTenantRequest {
    /// Only `"canceled"` is accepted (cancels the subscription + cascades networks).
    pub subscription_status: String,
}

// ── Tenants — web/human auth (WS-F, ADR-0009) ───────────────────────────────────

/// Request body for `POST /v1/auth/password/signup`. The `code` is the one-time email
/// proof (gate 1); on success a session cookie is set.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PasswordSignupRequest {
    pub email: String,
    /// The one-time signup code issued to `email` (via
    /// `POST /v1/verification-codes {purpose: "signup"}`).
    pub code: String,
    /// Plaintext password (hashed server-side; never stored or logged).
    pub password: String,
}

/// Request body for `POST /v1/auth/password/login`. On success a session cookie is set.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PasswordLoginRequest {
    pub email: String,
    pub password: String,
}

/// Request body for `POST /v1/auth/password/reset`. The `code` is the one-time email
/// proof; the new password replaces (or sets) the account's password and force-logs-out
/// every session.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PasswordResetRequest {
    pub code: String,
    pub password: String,
}

/// Request body for `POST /v1/me/password` — an **authenticated** USER sets or changes
/// their own password. The `code` is a fresh one-time email proof (issued via
/// `POST /v1/verification-codes {purpose: "password_change"}`) and must be for the
/// caller's own account email. On success every existing session is revoked and a new
/// session cookie is issued for the current browser, so the user stays signed in.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SetPasswordRequest {
    /// One-time email-proof code for the caller's account email.
    pub code: String,
    /// Plaintext new password (hashed server-side; never stored or logged).
    pub password: String,
}

/// Account profile for the SPA (`GET /v1/me`, auth = `USER`). The full current-user
/// view: the tenant identity + its current subscription.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MeView {
    /// The user's tenant id (`sub`).
    pub tenant_id: String,
    pub email: String,
    /// The tenant's current (non-`Canceled`) subscription, or `None` if not entitled.
    pub subscription: Option<SubscriptionView>,
}

// ── Tenants — account-plane billing (Stripe) ────────────────────────────────────

/// Request body for `POST /v1/tenants/{id}/billing/checkout-session`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateCheckoutSessionRequest {
    /// The Stripe Price id of the plan being purchased.
    pub price_id: String,
    /// Set by the SPA only on the **re-confirm** after a [`PromoUnavailableBody`] 409:
    /// the customer has acknowledged the (now full) price, so the server skips applying
    /// any auto-promo and proceeds at the catalog price. Defaults to `false`.
    #[serde(default)]
    pub accept_full_price: bool,
}

/// Response body for the create-checkout-session endpoint. Also returned by the
/// card-update (setup-mode Checkout) endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CheckoutSessionResponse {
    /// The Stripe-hosted Checkout URL to redirect the user to.
    pub url: String,
}

/// One purchasable [plan](`crate::contract`) row for `GET /v1/plans` (newest catalog,
/// ascending by [`level`](Self::level)). The whole catalog is sourced from Stripe and
/// served from the Billing projection; this is its public, tenant-agnostic display shape.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PlanView {
    /// The Stripe Price id Checkout / change-plan is created against.
    pub price_id: String,
    /// Human-facing plan name (the Stripe product name).
    pub name: String,
    /// The unique integer rank that totally orders the catalog (Stripe price metadata
    /// `level`). Higher = more. Drives the upgrade/downgrade decision.
    pub level: u32,
    /// The limits this plan grants (from the price's `max_networks`/`max_daemons` metadata).
    pub entitlement: Entitlement,
    /// The plan's list price in the currency's minor units (e.g. cents) — before any promo.
    pub amount_cents: i64,
    /// ISO-4217 currency code, lowercase (e.g. `"usd"`).
    pub currency: String,
    /// Billing interval as Stripe reports it (`"month"` / `"year"`). Never assumed.
    pub interval: String,
    /// A live global promotion for this plan, or `None`. **Display-only** — the discount
    /// is re-derived and applied server-side at Checkout/upgrade, never trusted from here.
    pub promo: Option<PromoView>,
}

/// The display half of a live [promotion](`PlanView::promo`) on a [`PlanView`]. The
/// discounted amount is computed server-side from the Stripe coupon; the SPA only renders it.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PromoView {
    /// The post-discount price in the currency's minor units (what the customer pays now).
    pub amount_cents_after: i64,
    /// Human-facing label for the promotion (the Stripe coupon name).
    pub label: String,
    /// When the promotion's window closes (the Stripe coupon `redeem_by`).
    pub ends_at: DateTime<Utc>,
}

/// Request body for `POST /v1/tenants/{id}/billing/change-plan`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ChangePlanRequest {
    /// The Stripe Price id of the **target** plan.
    pub price_id: String,
    /// Re-confirm flag after a [`PromoUnavailableBody`] 409 (see
    /// [`CreateCheckoutSessionRequest::accept_full_price`]). Defaults to `false`.
    #[serde(default)]
    pub accept_full_price: bool,
}

/// What a [change-plan](ChangePlanRequest) did. The actual entitlement change lands
/// asynchronously via the Stripe webhook — this only reports the effect + when it takes hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanChangeEffect {
    /// Target level > current: applied immediately (proration on the next invoice).
    Upgraded,
    /// Target level < current: scheduled to take effect at the current period end.
    DowngradeScheduled,
    /// Re-selected the current plan while a downgrade was pending: the pending downgrade
    /// was released, so the tenant stays on the current plan.
    DowngradeCanceled,
}

/// Response body for the change-plan endpoint (`202 Accepted`).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ChangePlanResponse {
    /// What happened.
    pub effect: PlanChangeEffect,
    /// When the change takes effect — the period end for a scheduled downgrade; `None`
    /// for an immediate upgrade or a canceled downgrade.
    pub effective_at: Option<DateTime<Utc>>,
    /// The Stripe Price the tenant is on *after* this change — the target for an
    /// immediate upgrade, the unchanged current price for a scheduled/canceled downgrade.
    /// Lets the SPA reflect the new current plan at once instead of waiting on the async
    /// webhook that back-fills `billing_customers` (kills the post-upgrade UI lag).
    pub current_price_id: Option<String>,
}

/// The provider (Billing) view of a tenant's subscription for the account page —
/// the bits that live in Billing (Stripe refs), composed by the SPA alongside the
/// provider-agnostic [`SubscriptionView`]. Response for
/// `GET /v1/tenants/{id}/billing/subscription`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BillingSubscriptionView {
    /// The Stripe Price id the tenant is currently subscribed at, or `None` (no paid
    /// subscription — trial/canceled). Lets the SPA highlight the current plan in the picker.
    pub current_price_id: Option<String>,
    /// A pending scheduled downgrade (read from the Stripe subscription schedule), or
    /// `None`. Survives reloads so the "downgrades on DATE" banner can re-render.
    pub pending_change: Option<PendingChangeView>,
    /// Whether the subscription is still in its Stripe trial (a *trial-preserving* Home
    /// sub, ADR-0012). The SPA uses this to confirm before an in-app upgrade that would
    /// end the trial — the account state alone can't tell (a honored trial reads `Active`).
    pub trialing: bool,
}

/// A pending scheduled plan change (today only a downgrade), surfaced by
/// [`BillingSubscriptionView`].
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PendingChangeView {
    /// The Stripe Price id the subscription will move to at [`effective_at`](Self::effective_at).
    pub price_id: String,
    /// The target plan's name (resolved through the catalog projection).
    pub name: String,
    /// The target plan's level.
    pub level: u32,
    /// When the scheduled change takes effect (the current period end).
    pub effective_at: DateTime<Utc>,
}

/// `409` body returned by checkout / change-plan when an auto-promo that was displayed
/// has lapsed by the time it is applied (Stripe rejects the coupon). The SPA shows the
/// real price and re-confirms with `accept_full_price = true`. Carries the structured
/// price so the SPA need not re-fetch the catalog to render the prompt.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PromoUnavailableBody {
    /// Machine tag for the SPA to branch on (`"promo_unavailable"`).
    pub error: String,
    /// The plan's full price in the currency's minor units (no discount).
    pub actual_amount_cents: i64,
    /// ISO-4217 currency code, lowercase.
    pub currency: String,
}

/// The tenant's default payment-method summary, read back from the provider for
/// `GET /v1/tenants/{id}/billing/payment-method`.
///
/// These fields are **not** PAN/CVC — `last4`/`brand`/`exp_*` are safe to read and render
/// (SAQ-A preserved; card *entry* still happens only through hosted Checkout/Portal). The
/// endpoint returns `null` when the tenant has no provider customer / default card yet.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PaymentMethodView {
    /// Card brand, e.g. `"visa"`.
    pub brand: String,
    /// The last four digits of the card number, e.g. `"4242"`.
    pub last4: String,
    /// Expiry month, `1`–`12`.
    pub exp_month: u32,
    /// Expiry year, four digits, e.g. `2027`.
    pub exp_year: u32,
}

/// Provider-agnostic invoice lifecycle status (mapped from the provider's own set).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, utoipa::ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InvoiceStatus {
    Paid,
    Open,
    Void,
    Uncollectible,
}

/// One invoice row for `GET /v1/tenants/{id}/billing/invoices` (newest first in the list).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct InvoiceView {
    /// Invoice creation date as `YYYY-MM-DD`.
    pub date: String,
    /// Amount in the currency's minor units (e.g. cents); the SPA formats for display.
    pub amount_cents: i64,
    /// ISO-4217 currency code, lowercase (e.g. `"usd"`), as the provider reports it.
    pub currency: String,
    /// Provider-agnostic status.
    pub status: InvoiceStatus,
    /// The provider-hosted invoice/receipt URL (the download action); `None` if absent.
    pub hosted_url: Option<String>,
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
