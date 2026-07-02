//! Synchronous inter-aggregate **client ports** — the query/command seams between
//! the (currently in-process) aggregates that need an answer *now*, not eventually.
//!
//! These traits live in `common` on purpose: the aggregate crates (`tenants`,
//! `subscriptions`, `billing`) depend on `common` and **never on each other**, so a
//! consumer can only ever name an `Arc<dyn Port>` here — the compiler forbids it from
//! reaching a sibling's concrete type. That boundary is exactly what becomes a
//! network call when an aggregate is promoted to its own host: today the composition
//! root injects an in-process adapter (a direct method call); later it injects a
//! mesh-mTLS HTTP adapter, with **zero** change to the consuming domain code.
//!
//! Two directions, mirroring the established Identities → Tenants edge:
//! - [`SubscriptionReader`] — entitlement **reads** (Tenants' `register_network` /
//!   daemon JWT minting, the resource-read view, the Tunneller's `TenantView`).
//! - [`SubscriptionCommands`] — the one-way **Billing → Subscription** write edge
//!   (the webhook drives license transitions only through this). Subscription never
//!   calls Billing.
//!
//! Only `common` types cross the boundary (no concrete domain struct): reads return
//! the [`SubscriptionView`](crate::contract::SubscriptionView) DTO; commands take
//! primitives + [`Entitlement`](crate::contract::Entitlement).

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::contract::{
    BillingSubscriptionView, ChangePlanResponse, Entitlement, InvoiceView, PaymentMethodView,
    PlanView, SubscriptionStatus, SubscriptionView,
};
use crate::error::ApiError;

/// Read port over the **license** (subscription) aggregate. In-process adapter =
/// a direct call into `SubscriptionService`.
#[async_trait]
pub trait SubscriptionReader: Send + Sync {
    /// The tenant's current (single non-`Canceled`) subscription as a wire view, or
    /// `None` if it has no live subscription.
    ///
    /// # Errors
    /// Propagates a backing-store / transport failure.
    async fn current(&self, tenant_id: &str) -> anyhow::Result<Option<SubscriptionView>>;

    /// Whether the tenant is **currently entitled** to service, applying the trial /
    /// payment **grace** windows (the policy lives with the aggregate, so this is
    /// computed provider-side, not re-derived by the caller).
    ///
    /// # Errors
    /// Propagates a backing-store / transport failure.
    async fn is_active(&self, tenant_id: &str) -> anyhow::Result<bool>;
}

/// Command port over the **license** aggregate — the one-way Billing → Subscription
/// edge. Implemented by `SubscriptionService`; called by Billing's webhook path. The
/// `stripe_*` reference ids never cross here (they live in Billing's own
/// `billing_customers` table), so every transition is provider-agnostic.
#[async_trait]
pub trait SubscriptionCommands: Send + Sync {
    /// Convert the tenant's trial to a paid subscription (cancel the live trial +
    /// insert the paid row, atomically) at the provider-reported `status` (never
    /// `Canceled` — cancellation routes through [`cancel`](Self::cancel)). Used both
    /// for the first paid event and to recreate a paid license that lapsed.
    ///
    /// # Errors
    /// Propagates a backing-store / transport failure.
    async fn convert_trial_to_paid(
        &self,
        tenant_id: &str,
        status: SubscriptionStatus,
        entitlement: Entitlement,
        current_period_end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<()>;

    /// Reconcile the tenant's live paid subscription to a provider update — a plan
    /// change / period roll / `active`⇄`past_due` refresh. `status` is the provider's
    /// reported lifecycle (never `Canceled` here — cancellation routes through
    /// [`cancel`](Self::cancel)). Returns `false` if the tenant has no live
    /// subscription.
    ///
    /// # Errors
    /// Propagates a backing-store / transport failure.
    async fn update_paid(
        &self,
        tenant_id: &str,
        status: SubscriptionStatus,
        entitlement: Entitlement,
        current_period_end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<bool>;

    /// Flag the tenant's live subscription `past_due` (a payment failed), preserving
    /// its entitlement + period. Returns `false` if the tenant has no live
    /// subscription.
    ///
    /// # Errors
    /// Propagates a backing-store / transport failure.
    async fn mark_past_due(&self, tenant_id: &str) -> anyhow::Result<bool>;

    /// Cancel the tenant's current subscription (publishing
    /// [`SubscriptionDeactivated`](crate::event::DomainEvent::SubscriptionDeactivated)
    /// so the network reactor deprovisions its networks). Idempotent.
    ///
    /// # Errors
    /// Propagates a backing-store / transport failure.
    async fn cancel(&self, tenant_id: &str) -> anyhow::Result<()>;
}

/// Read port over the **plan catalog** — the set of purchasable plans + live
/// promotions. Sourced from Stripe, served from the Billing projection (never a live
/// Stripe call on the hot path). Implemented by `BillingService`; consumed by the public
/// `GET /v1/plans` handler.
#[async_trait]
pub trait PlanCatalog: Send + Sync {
    /// The purchasable plans, ascending by [`level`](crate::contract::PlanView::level),
    /// each carrying any live promotion's discounted price (computed against the current
    /// clock at call time).
    ///
    /// # Errors
    /// [`BillingError::Internal`] on a repository failure, or [`BillingError::Stale`]
    /// when the projection is older than the hard staleness bound (→ `503`).
    async fn plans(&self) -> Result<Vec<PlanView>, BillingError>;
}

/// Error surfaced by the [`BillingPort`] / [`PlanCatalog`]. HTTP-agnostic but
/// distinguishes the client-fixable / display cases from an internal failure, so the
/// HTTP shell maps each to the right status.
#[derive(Debug, thiserror::Error)]
pub enum BillingError {
    /// The request itself is bad — an unverifiable webhook signature, a change-plan on a
    /// tenant with no paid subscription, or an unknown target plan. Maps to `400`.
    #[error("{0}")]
    InvalidRequest(String),
    /// A displayed auto-promo had lapsed by the time it was applied (the provider
    /// rejected the coupon). Carries the real price so the caller can re-confirm at full
    /// price. Maps to `409` ([`PromoUnavailableBody`](crate::contract::PromoUnavailableBody)).
    #[error("promotion no longer available")]
    PromoUnavailable {
        /// The plan's full price in the currency's minor units.
        actual_amount_cents: i64,
        /// ISO-4217 currency code, lowercase.
        currency: String,
    },
    /// The catalog projection is too stale to trust (the sync worker has not refreshed it
    /// within the hard bound). Maps to `503` — we never serve ancient pricing.
    #[error("plan catalog temporarily unavailable")]
    Stale,
    /// A provider/repository failure. Maps to `500`.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<BillingError> for ApiError {
    fn from(e: BillingError) -> Self {
        match e {
            BillingError::InvalidRequest(m) => ApiError::BadRequest(m),
            // PromoUnavailable carries structured data the SPA needs; the change-plan /
            // checkout handlers render it as a 409 directly. Reaching the generic mapping
            // (it shouldn't) degrades to a 409 with a plain message.
            BillingError::PromoUnavailable { .. } => {
                ApiError::Conflict("promotion no longer available".to_string())
            }
            BillingError::Stale => {
                ApiError::ServiceUnavailable("plan catalog temporarily unavailable".to_string())
            }
            BillingError::Internal(e) => ApiError::Internal(e),
        }
    }
}

/// Command port over the **payment** (billing) aggregate — the
/// composition/Tenants → Billing edge. Implemented by `BillingService`; consumed by
/// the HTTP handlers (hosted in the deployable's router today; served by Billing's
/// own bin after a future split, where the webhook is delivered to Billing directly
/// and checkout/portal arrive over mesh-mTLS). Billing never calls back.
#[async_trait]
pub trait BillingPort: Send + Sync {
    /// Start a hosted Checkout for `price_id` (reusing the tenant's provider customer
    /// when known) and return the redirect URL. Auto-applies the plan's live promotion
    /// server-side unless `accept_full_price` is set (the re-confirm after a
    /// [`PromoUnavailable`](BillingError::PromoUnavailable) prompt).
    ///
    /// # Errors
    /// [`BillingError::PromoUnavailable`] if a displayed promo lapsed before it could be
    /// applied; [`BillingError::Internal`] on a provider/repository failure.
    async fn start_checkout(
        &self,
        tenant_id: &str,
        email: &str,
        price_id: &str,
        accept_full_price: bool,
    ) -> Result<String, BillingError>;

    /// Change an **already-paid** tenant's plan to `price_id`. An upgrade (higher
    /// [`level`](crate::contract::PlanView::level)) applies immediately; a downgrade is
    /// scheduled for the current period end; re-selecting the current plan cancels any
    /// pending downgrade. Auto-applies the live promo on an upgrade unless
    /// `accept_full_price`.
    ///
    /// # Errors
    /// [`BillingError::InvalidRequest`] if the tenant has no paid subscription, or
    /// `price_id` is unknown / equals the current plan with nothing pending;
    /// [`BillingError::PromoUnavailable`] if a displayed promo lapsed;
    /// [`BillingError::Internal`] on a provider/repository failure.
    async fn change_plan(
        &self,
        tenant_id: &str,
        price_id: &str,
        accept_full_price: bool,
    ) -> Result<ChangePlanResponse, BillingError>;

    /// Start a hosted `setup`-mode Checkout to add/replace the tenant's card (no
    /// purchase) and return its URL. Replaces the removed Customer Portal card-update.
    ///
    /// # Errors
    /// [`BillingError::InvalidRequest`] if the tenant has no billing account yet;
    /// [`BillingError::Internal`] on a provider failure.
    async fn start_card_update(&self, tenant_id: &str) -> Result<String, BillingError>;

    /// The provider (Billing) view of the tenant's subscription — its current Stripe
    /// price and any pending scheduled downgrade — for the account page.
    ///
    /// # Errors
    /// [`BillingError::Internal`] on a provider/repository failure.
    async fn billing_subscription(
        &self,
        tenant_id: &str,
    ) -> Result<BillingSubscriptionView, BillingError>;

    /// Verify a raw provider webhook (the signature is the credential) and apply it
    /// idempotently.
    ///
    /// # Errors
    /// [`BillingError::InvalidRequest`] on an unverifiable/malformed payload;
    /// [`BillingError::Internal`] on a repository failure.
    async fn handle_webhook(&self, payload: &[u8], signature: &str) -> Result<(), BillingError>;

    /// The tenant's default payment-method summary (provider-proxied read), or `None`
    /// when the tenant has no provider customer / default card yet. Never PAN/CVC — only
    /// the brand/last4/expiry the SPA renders (SAQ-A safe).
    ///
    /// # Errors
    /// [`BillingError::Internal`] on a provider/repository failure.
    async fn payment_method(
        &self,
        tenant_id: &str,
    ) -> Result<Option<PaymentMethodView>, BillingError>;

    /// The tenant's recent invoices, newest first (provider-proxied read). An empty list
    /// when the tenant has no provider customer / invoices.
    ///
    /// # Errors
    /// [`BillingError::Internal`] on a provider/repository failure.
    async fn invoices(&self, tenant_id: &str) -> Result<Vec<InvoiceView>, BillingError>;
}
