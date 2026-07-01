//! `BillingService` — owns *how a subscription is paid for*: hosted Checkout/Portal,
//! the Stripe webhook, the provider-reference table, and the idempotency ledger.
//!
//! It drives the **license** aggregate exclusively through the
//! [`SubscriptionReader`] / [`SubscriptionCommands`] ports — it never names a
//! `subscriptions` (or `tenants`) type, so the boundary is compiler-enforced
//! (ADR-0010). Subscription never calls Billing back.

use std::cmp::Ordering;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use tokio::sync::Notify;

use wardnet_common::contract::{
    BillingSubscriptionView, ChangePlanResponse, Entitlement, InvoiceView, PaymentMethodView,
    PendingChangeView, PlanChangeEffect, PlanView, PromoView, SubscriptionStatus,
};
use wardnet_common::ports::{
    BillingError, BillingPort, PlanCatalog, SubscriptionCommands, SubscriptionReader,
};

use crate::gateway::{
    CouponRejected, PlanData, PromotionData, ScheduledChange, StripeEvent, StripeEventKind,
    StripeGateway, SubscriptionData,
};
use crate::repository::{BillingRepository, CatalogPlan, CatalogPromo, CatalogSnapshot};

/// Minimum remaining trial (hours) for a trial-preserving subscribe to defer the first
/// charge — below this, Stripe would reject the near/past `trial_end`, so we charge
/// immediately instead (ADR-0012). Reflects Stripe's minimum `trial_end` lead time.
const TRIAL_PRESERVE_MIN_HOURS: i64 = 48;

/// The payment business-rule layer.
pub struct BillingService {
    stripe: Arc<dyn StripeGateway>,
    billing: Arc<dyn BillingRepository>,
    /// Read the license aggregate (e.g. preserve entitlement on a provider update
    /// that carries no price metadata).
    subscription_reader: Arc<dyn SubscriptionReader>,
    /// The one-way Billing → Subscription write edge.
    subscription_commands: Arc<dyn SubscriptionCommands>,
    /// Pinged when a Stripe catalog webhook arrives, so the sync worker resyncs the
    /// projection promptly (the periodic loop is the backstop).
    catalog_resync: Arc<Notify>,
    /// How old the catalog projection may be before `plans()` refuses to serve it (503).
    catalog_stale: Duration,
}

impl BillingService {
    #[must_use]
    pub fn new(
        stripe: Arc<dyn StripeGateway>,
        billing: Arc<dyn BillingRepository>,
        subscription_reader: Arc<dyn SubscriptionReader>,
        subscription_commands: Arc<dyn SubscriptionCommands>,
        catalog_resync: Arc<Notify>,
        catalog_stale_secs: i64,
    ) -> Self {
        Self {
            stripe,
            billing,
            subscription_reader,
            subscription_commands,
            catalog_resync,
            catalog_stale: Duration::seconds(catalog_stale_secs),
        }
    }

    /// A handle the composition root passes to the catalog-sync worker, so a Stripe
    /// catalog webhook can wake it between periodic ticks.
    #[must_use]
    pub fn catalog_resync_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.catalog_resync)
    }

    /// Best-effort restore of a pending scheduled downgrade that was released before a
    /// plan-change attempt that then failed (so the user doesn't silently lose it). A
    /// failure to restore is logged, not surfaced — the caller is already returning the
    /// original error, and the periodic reconcile / a later user action can re-establish it.
    async fn restore_pending(
        &self,
        subscription_id: &str,
        current_price_id: &str,
        prior: Option<&ScheduledChange>,
        boundary: chrono::DateTime<Utc>,
    ) {
        let Some(prior) = prior else { return };
        if let Err(e) = self
            .stripe
            .schedule_downgrade(subscription_id, current_price_id, &prior.price_id, boundary)
            .await
        {
            tracing::error!(
                subscription_id,
                error = %e,
                "failed to restore pending downgrade after a failed plan change"
            );
        }
    }

    /// Resync the catalog projection from Stripe: list plans + promotions, validate, and
    /// replace the projection atomically. Called by the sync worker (on its interval and
    /// on a catalog-webhook ping), never on the request hot path.
    ///
    /// A plan missing a parseable entitlement or a unique integer `level` is dropped
    /// (safe-closed); a `level` shared by two plans drops **all** plans at that level
    /// (an ambiguous catalog must not silently pick one). Only `wardnet_auto_apply`
    /// coupons are kept.
    ///
    /// # Errors
    /// Propagates a provider/repository failure.
    pub async fn sync_catalog(&self) -> anyhow::Result<()> {
        let raw_plans = self.stripe.list_plans().await?;
        let raw_promos = self.stripe.list_promotions().await?;
        let plans = validate_plans(raw_plans);
        let promos = validate_promos(raw_promos);
        self.billing
            .replace_catalog(&plans, &promos, Utc::now())
            .await?;
        tracing::info!(
            plans = plans.len(),
            promotions = promos.len(),
            "catalog projection synced from Stripe"
        );
        Ok(())
    }

    /// Apply a verified Stripe webhook event, idempotently (a redelivery whose id is
    /// already recorded is a no-op). The id is recorded only **after** a successful
    /// apply, so a failed apply stays un-recorded and Stripe's retry re-applies it.
    async fn apply_event(&self, event: StripeEvent) -> Result<(), BillingError> {
        if self.billing.is_event_processed(&event.id).await? {
            tracing::debug!(event_id = %event.id, "stripe event already processed; skipping");
            return Ok(());
        }
        self.apply_event_kind(event.kind).await?;
        self.billing.record_event(&event.id, Utc::now()).await?;
        Ok(())
    }

    /// Apply the event's effect. Each branch is idempotent, so an at-least-once
    /// redelivery (or a retry after a recorded-but-failed apply) is safe.
    async fn apply_event_kind(&self, kind: StripeEventKind) -> Result<(), BillingError> {
        match kind {
            StripeEventKind::SubscriptionUpsert(data) => self.apply_upsert(data).await?,
            StripeEventKind::SubscriptionDeleted {
                stripe_subscription_id,
            } => {
                if let Some(tenant_id) = self
                    .billing
                    .tenant_for_subscription(&stripe_subscription_id)
                    .await?
                {
                    self.subscription_commands.cancel(&tenant_id).await?;
                }
            }
            StripeEventKind::PaymentFailed {
                stripe_subscription_id,
            } => {
                if let Some(tenant_id) = self
                    .billing
                    .tenant_for_subscription(&stripe_subscription_id)
                    .await?
                {
                    self.subscription_commands.mark_past_due(&tenant_id).await?;
                }
            }
            // A card was added/replaced via a setup-mode Checkout → promote it to the
            // customer's + subscription's default, or renewals keep charging the old card.
            StripeEventKind::CardSetupCompleted {
                stripe_customer_id,
                setup_intent_id,
            } => {
                let subscription_id = self
                    .billing
                    .subscription_for_customer(&stripe_customer_id)
                    .await?;
                self.stripe
                    .set_default_payment_method_from_setup(
                        &stripe_customer_id,
                        subscription_id.as_deref(),
                        &setup_intent_id,
                    )
                    .await
                    .map_err(BillingError::Internal)?;
            }
            // A catalog object changed in Stripe → wake the sync worker (it re-lists the
            // whole catalog). We do NOT call Stripe inline here — the webhook must stay
            // fast — and the periodic loop is the backstop for a missed ping.
            StripeEventKind::CatalogChanged => self.catalog_resync.notify_one(),
            StripeEventKind::Ignored => {}
        }
        Ok(())
    }

    /// `customer.subscription.created`/`.updated`: record the provider refs and drive
    /// the license aggregate to the reported state.
    ///
    /// The convert-vs-update decision is made on the **license state** (read via the
    /// port), not on whether we have already recorded the provider ref. That keeps two
    /// at-least-once properties the old single-aggregate code had implicitly: a retry
    /// after a partial write still *converts* (rather than mutating the still-trial row
    /// in place), and a renewed subscription whose license the reaper already canceled
    /// re-entitles by recreating the paid row.
    async fn apply_upsert(&self, data: SubscriptionData) -> Result<(), BillingError> {
        // Resolve the tenant: the recorded provider-ref mapping first (an `.updated`
        // payload may omit checkout metadata), else the checkout metadata (a never-seen
        // subscription). `known` also tells us whether this subscription is one we have
        // actually recorded — only those are cancellable.
        let known = self
            .billing
            .tenant_for_subscription(&data.stripe_subscription_id)
            .await?;
        let Some(tenant_id) = known.clone().or_else(|| data.tenant_id.clone()) else {
            // No mapping and no metadata: a never-seen subscription we can't attribute.
            // Canceled is simply nothing-to-do; anything else is declined (safe-closed).
            if data.status != SubscriptionStatus::Canceled {
                tracing::error!(
                    stripe_subscription_id = %data.stripe_subscription_id,
                    "stripe subscription has no tenant_id metadata; ignoring"
                );
            }
            return Ok(());
        };

        // A reported Canceled routes through the single cancel path (publishes the
        // deactivation). Only cancel a subscription we have recorded — a never-seen
        // subscription reporting canceled has nothing to cancel (the tenant may still be
        // on its trial), matching the old new-vs-existing split.
        if data.status == SubscriptionStatus::Canceled {
            if let Some(tenant_id) = known {
                self.subscription_commands.cancel(&tenant_id).await?;
            }
            return Ok(());
        }

        // Read the current license once: its status picks convert-vs-update, and its
        // entitlement is the fallback when Stripe omits price metadata on an update.
        let current = self.subscription_reader.current(&tenant_id).await?;

        // Already a paid license → patch it in place, preserving the current
        // entitlement when Stripe omits price metadata. Otherwise (no live license — e.g.
        // the reaper canceled it — or still on the trial) (re)create the paid license,
        // carrying Stripe's reported status.
        //
        // The provider ref is recorded only **after** we commit to granting (and before
        // the license command, so a retry still maps the subscription to its tenant). A
        // subscription we decline to grant (no price metadata) must NOT be recorded —
        // otherwise a later `.deleted`/`.payment_failed` would resolve this tenant and
        // wrongly cancel/past-due its still-live trial.
        if matches!(
            current.as_ref().map(|s| s.status),
            Some(SubscriptionStatus::Active | SubscriptionStatus::PastDue)
        ) {
            let entitlement = data
                .entitlement
                .or_else(|| current.map(|s| s.entitlement))
                .unwrap_or(Entitlement::DEFAULT);
            self.record_ref(&tenant_id, &data).await?;
            self.subscription_commands
                .update_paid(
                    &tenant_id,
                    data.status,
                    entitlement,
                    data.current_period_end,
                )
                .await?;
        } else {
            // The plan's entitlement must come from price metadata; without it we
            // decline to grant (safe-closed) and record nothing.
            let Some(entitlement) = data.entitlement else {
                tracing::error!(
                    stripe_subscription_id = %data.stripe_subscription_id,
                    "stripe price has no max_networks/max_daemons metadata; not granting"
                );
                return Ok(());
            };
            self.record_ref(&tenant_id, &data).await?;
            self.subscription_commands
                .convert_trial_to_paid(
                    &tenant_id,
                    data.status,
                    entitlement,
                    data.current_period_end,
                )
                .await?;
            tracing::info!(tenant_id, "converted to paid subscription");
        }
        Ok(())
    }

    /// Record the provider refs (idempotent) so future webhooks for this subscription
    /// resolve back to its tenant. Called only once we have committed to grant/update —
    /// never on a declined subscription (see [`apply_upsert`](Self::apply_upsert)).
    async fn record_ref(
        &self,
        tenant_id: &str,
        data: &SubscriptionData,
    ) -> Result<(), BillingError> {
        self.billing
            .upsert_subscription(
                tenant_id,
                &data.stripe_customer_id,
                &data.stripe_subscription_id,
                data.price_id.as_deref(),
            )
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl BillingPort for BillingService {
    async fn start_checkout(
        &self,
        tenant_id: &str,
        email: &str,
        price_id: &str,
        accept_full_price: bool,
    ) -> Result<String, BillingError> {
        let customer_id = self.billing.customer_id(tenant_id).await?;
        // Re-derive the live promo server-side (the SPA never passes a coupon), unless the
        // customer has just re-confirmed at full price after a PromoUnavailable prompt.
        let snapshot = self.billing.read_catalog().await?;
        let now = Utc::now();
        let coupon = if accept_full_price {
            None
        } else {
            live_coupon_for_price(&snapshot, price_id, now)
        };
        // Trial-preserving subscribe (ADR-0012): if the tenant is still on the managed
        // trial and the chosen plan grants no more than the trial (Home), defer the first
        // charge to the original trial end so they keep their remaining free days. A higher
        // tier, an already-expired trial, or a window too short for Stripe falls through to
        // an immediate charge.
        let trial_end = self
            .subscription_reader
            .current(tenant_id)
            .await?
            .filter(|s| s.status == SubscriptionStatus::Trialing)
            .and_then(|s| {
                let target = snapshot.plans.iter().find(|p| p.price_id == price_id)?;
                let within_trial = target.entitlement.max_networks <= s.entitlement.max_networks
                    && target.entitlement.max_daemons <= s.entitlement.max_daemons;
                let expires = s.trial_expires_at?;
                // Stripe requires `trial_end` to be a safely-future timestamp.
                (within_trial && expires > now + Duration::hours(TRIAL_PRESERVE_MIN_HOURS))
                    .then(|| expires.timestamp())
            });
        let session = match self
            .stripe
            .create_checkout_session(
                customer_id.as_deref(),
                email,
                price_id,
                tenant_id,
                coupon.as_deref(),
                trial_end,
            )
            .await
        {
            Ok(s) => s,
            Err(e) => return Err(promo_aware_error(e, &snapshot, price_id)),
        };
        // Best-effort: stamp the customer id now if Stripe surfaced one (the
        // authoritative value still arrives via the webhook).
        if let Some(cid) = session.customer_id {
            self.billing.upsert_customer(tenant_id, &cid).await?;
        }
        Ok(session.url)
    }

    #[allow(clippy::too_many_lines)] // one linear flow: resolve → release-then-act → restore-on-fail
    async fn change_plan(
        &self,
        tenant_id: &str,
        price_id: &str,
        accept_full_price: bool,
    ) -> Result<ChangePlanResponse, BillingError> {
        // A paid subscription is required — a trial/canceled tenant has no Stripe
        // subscription to mutate (it subscribes via Checkout instead).
        let subscription_id = self
            .billing
            .billing_ref(tenant_id)
            .await?
            .and_then(|r| r.stripe_subscription_id)
            .ok_or_else(|| {
                BillingError::InvalidRequest("no paid subscription to change".to_string())
            })?;

        let snapshot = self.billing.read_catalog().await?;
        let target = snapshot
            .plans
            .iter()
            .find(|p| p.price_id == price_id)
            .ok_or_else(|| BillingError::InvalidRequest("unknown plan".to_string()))?;

        // Live details: the item to swap, current price/level, period end, any schedule.
        let details = self
            .stripe
            .get_subscription(&subscription_id)
            .await
            .map_err(BillingError::Internal)?;
        let current_level = snapshot
            .plans
            .iter()
            .find(|p| p.price_id == details.price_id)
            .map(|p| p.level)
            .ok_or_else(|| {
                BillingError::InvalidRequest("current plan not in catalog".to_string())
            })?;

        // Re-entry: always reconcile against an existing schedule first (release-then-act),
        // so a pending downgrade never compounds and re-selecting the current plan cancels it.
        // Capture the pending change *before* releasing, so a failed act below can restore
        // it — release-then-act must not silently drop the user's pending downgrade.
        let had_pending = details.schedule_id.is_some();
        let prior_pending = if let Some(schedule_id) = &details.schedule_id {
            self.stripe
                .pending_scheduled_change(schedule_id, details.current_period_end)
                .await
                .map_err(BillingError::Internal)?
        } else {
            None
        };
        if let Some(schedule_id) = &details.schedule_id {
            self.stripe
                .release_schedule(schedule_id)
                .await
                .map_err(BillingError::Internal)?;
        }

        match target.level.cmp(&current_level) {
            Ordering::Equal => {
                if had_pending {
                    Ok(ChangePlanResponse {
                        effect: PlanChangeEffect::DowngradeCanceled,
                        effective_at: None,
                        current_price_id: Some(details.price_id.clone()),
                    })
                } else {
                    Err(BillingError::InvalidRequest(
                        "already on this plan".to_string(),
                    ))
                }
            }
            Ordering::Greater => {
                let coupon = if accept_full_price {
                    None
                } else {
                    live_coupon_for_price(&snapshot, price_id, Utc::now())
                };
                match self
                    .stripe
                    .upgrade_subscription(
                        &subscription_id,
                        &details.item_id,
                        price_id,
                        coupon.as_deref(),
                        // A trial-preserving sub always sits on Home, so any upgrade
                        // exceeds the trial entitlement and ends the trial (ADR-0012).
                        details.trialing,
                    )
                    .await
                {
                    Ok(()) => Ok(ChangePlanResponse {
                        effect: PlanChangeEffect::Upgraded,
                        effective_at: None,
                        // The upgrade is immediate, so the target price is now current.
                        current_price_id: Some(price_id.to_string()),
                    }),
                    Err(e) => {
                        self.restore_pending(
                            &subscription_id,
                            &details.price_id,
                            prior_pending.as_ref(),
                            details.current_period_end,
                        )
                        .await;
                        Err(promo_aware_error(e, &snapshot, price_id))
                    }
                }
            }
            Ordering::Less => {
                match self
                    .stripe
                    .schedule_downgrade(
                        &subscription_id,
                        &details.price_id,
                        price_id,
                        details.current_period_end,
                    )
                    .await
                {
                    Ok(effective_at) => Ok(ChangePlanResponse {
                        effect: PlanChangeEffect::DowngradeScheduled,
                        effective_at: Some(effective_at),
                        // The downgrade is scheduled; the current price is unchanged now.
                        current_price_id: Some(details.price_id.clone()),
                    }),
                    Err(e) => {
                        self.restore_pending(
                            &subscription_id,
                            &details.price_id,
                            prior_pending.as_ref(),
                            details.current_period_end,
                        )
                        .await;
                        Err(BillingError::Internal(e))
                    }
                }
            }
        }
    }

    async fn start_card_update(&self, tenant_id: &str) -> Result<String, BillingError> {
        let bref = self
            .billing
            .billing_ref(tenant_id)
            .await?
            .unwrap_or_default();
        let customer_id = bref.customer_id.ok_or_else(|| {
            BillingError::InvalidRequest("tenant has no billing account yet".to_string())
        })?;
        // Match the setup session's currency to the tenant's current plan — setup mode has
        // no line items to infer it from. Falls back to USD when the plan can't be resolved.
        let currency = match &bref.price_id {
            Some(price_id) => {
                let snapshot = self.billing.read_catalog().await?;
                snapshot
                    .plans
                    .iter()
                    .find(|p| &p.price_id == price_id)
                    .map(|p| p.currency.clone())
            }
            None => None,
        }
        .unwrap_or_else(|| "usd".to_string());
        self.stripe
            .create_setup_checkout_session(&customer_id, &currency)
            .await
            .map_err(BillingError::Internal)
    }

    async fn billing_subscription(
        &self,
        tenant_id: &str,
    ) -> Result<BillingSubscriptionView, BillingError> {
        let Some(bref) = self.billing.billing_ref(tenant_id).await? else {
            return Ok(BillingSubscriptionView {
                current_price_id: None,
                pending_change: None,
                trialing: false,
            });
        };
        // One live read of the Stripe subscription gives both the trial flag (for the
        // in-app upgrade confirmation, ADR-0012) and the schedule id — only fetch the
        // pending-change detail when a schedule actually exists.
        let (trialing, pending_change) = match &bref.stripe_subscription_id {
            Some(sub_id) => {
                let details = self
                    .stripe
                    .get_subscription(sub_id)
                    .await
                    .map_err(BillingError::Internal)?;
                let pending_change = if let Some(schedule_id) = &details.schedule_id {
                    match self
                        .stripe
                        .pending_scheduled_change(schedule_id, details.current_period_end)
                        .await
                        .map_err(BillingError::Internal)?
                    {
                        Some(change) => {
                            let snapshot = self.billing.read_catalog().await?;
                            let plan = snapshot
                                .plans
                                .iter()
                                .find(|p| p.price_id == change.price_id);
                            Some(PendingChangeView {
                                name: plan
                                    .map_or_else(|| change.price_id.clone(), |p| p.name.clone()),
                                level: plan.map_or(0, |p| p.level),
                                price_id: change.price_id,
                                effective_at: change.effective_at,
                            })
                        }
                        None => None,
                    }
                } else {
                    None
                };
                (details.trialing, pending_change)
            }
            None => (false, None),
        };
        Ok(BillingSubscriptionView {
            current_price_id: bref.price_id,
            pending_change,
            trialing,
        })
    }

    async fn handle_webhook(&self, payload: &[u8], signature: &str) -> Result<(), BillingError> {
        let event = self
            .stripe
            .construct_event(payload, signature)
            .map_err(|e| BillingError::InvalidRequest(format!("invalid Stripe webhook: {e}")))?;
        self.apply_event(event).await
    }

    async fn payment_method(
        &self,
        tenant_id: &str,
    ) -> Result<Option<PaymentMethodView>, BillingError> {
        // A tenant with no provider customer (e.g. a card-less trial) has no payment
        // method — `null`, not an error.
        let Some(customer_id) = self.billing.customer_id(tenant_id).await? else {
            return Ok(None);
        };
        self.stripe
            .default_payment_method(&customer_id)
            .await
            .map_err(BillingError::Internal)
    }

    async fn invoices(&self, tenant_id: &str) -> Result<Vec<InvoiceView>, BillingError> {
        // No provider customer yet → no invoices (empty list, not an error).
        let Some(customer_id) = self.billing.customer_id(tenant_id).await? else {
            return Ok(Vec::new());
        };
        self.stripe
            .list_invoices(&customer_id)
            .await
            .map_err(BillingError::Internal)
    }
}

#[async_trait::async_trait]
impl PlanCatalog for BillingService {
    async fn plans(&self) -> Result<Vec<PlanView>, BillingError> {
        let snapshot = self.billing.read_catalog().await?;
        let now = Utc::now();
        // Refuse a catalog that has never synced or is past the hard staleness bound — we
        // never serve ancient pricing (→ 503).
        match snapshot.last_synced_at {
            Some(ts) if now - ts <= self.catalog_stale => {}
            _ => return Err(BillingError::Stale),
        }
        Ok(snapshot
            .plans
            .iter()
            .map(|plan| plan_view(plan, &snapshot.promos, now))
            .collect())
    }
}

/// Build a [`PlanView`] for `plan`, attaching its live promotion's discounted price (if any).
fn plan_view(plan: &CatalogPlan, promos: &[CatalogPromo], now: DateTime<Utc>) -> PlanView {
    let promo = best_live_promo(plan, promos, now).map(|c| PromoView {
        amount_cents_after: discounted_amount(plan.amount_cents, &plan.currency, c),
        label: c.name.clone(),
        // `redeem_by` is present for any promo that passed `is_live` (the window has an end).
        ends_at: c.redeem_by.unwrap_or(now),
    });
    PlanView {
        price_id: plan.price_id.clone(),
        name: plan.name.clone(),
        level: plan.level,
        entitlement: plan.entitlement,
        amount_cents: plan.amount_cents,
        currency: plan.currency.clone(),
        interval: plan.interval.clone(),
        promo,
    }
}

/// The live coupon id to auto-apply for `price_id` right now, or `None`. Re-derived
/// server-side at checkout/upgrade so a client can never inject a coupon.
fn live_coupon_for_price(
    snapshot: &CatalogSnapshot,
    price_id: &str,
    now: DateTime<Utc>,
) -> Option<String> {
    let plan = snapshot.plans.iter().find(|p| p.price_id == price_id)?;
    best_live_promo(plan, &snapshot.promos, now).map(|c| c.coupon_id.clone())
}

/// The best (largest-discount) live promotion applicable to `plan` right now, or `None`.
fn best_live_promo<'a>(
    plan: &CatalogPlan,
    promos: &'a [CatalogPromo],
    now: DateTime<Utc>,
) -> Option<&'a CatalogPromo> {
    promos
        .iter()
        .filter(|c| promo_is_live(c, plan, now))
        // Best for the customer = lowest resulting price.
        .min_by_key(|c| discounted_amount(plan.amount_cents, &plan.currency, c))
}

/// Whether promotion `c` applies to `plan` at `now`: its window contains `now` and its
/// product targeting covers the plan (an empty `applies_to` targets all plans).
fn promo_is_live(c: &CatalogPromo, plan: &CatalogPlan, now: DateTime<Utc>) -> bool {
    let started = c.start.is_none_or(|s| s <= now);
    // A promo with no `redeem_by` has no defined end → not eligible for the auto catalog
    // (we require a bounded window so `ends_at` is always meaningful).
    let not_ended = c.redeem_by.is_some_and(|e| now <= e);
    let targeted = c.applies_to_products.is_empty()
        || c.applies_to_products.iter().any(|p| p == &plan.product_id);
    started && not_ended && targeted
}

/// The price after applying coupon `c` to `amount_cents` (in `currency`), floored at 0.
/// An `amount_off` in a different currency than the plan does not apply.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)] // money is small (minor units); a cents-scale f64 round-trip is exact in practice
fn discounted_amount(amount_cents: i64, currency: &str, c: &CatalogPromo) -> i64 {
    if let Some(pct) = c.percent_off {
        let off = (amount_cents as f64 * pct / 100.0).round() as i64;
        return (amount_cents - off).max(0);
    }
    if let Some(off) = c.amount_off
        && c.currency.as_deref() == Some(currency)
    {
        return (amount_cents - off).max(0);
    }
    amount_cents
}

/// Map a gateway error from a coupon-bearing call to a [`BillingError`]: a
/// [`CouponRejected`] becomes a [`BillingError::PromoUnavailable`] carrying the plan's
/// full price (so the SPA can re-confirm), anything else is internal.
fn promo_aware_error(e: anyhow::Error, snapshot: &CatalogSnapshot, price_id: &str) -> BillingError {
    if e.downcast_ref::<CouponRejected>().is_some()
        && let Some(plan) = snapshot.plans.iter().find(|p| p.price_id == price_id)
    {
        return BillingError::PromoUnavailable {
            actual_amount_cents: plan.amount_cents,
            currency: plan.currency.clone(),
        };
    }
    BillingError::Internal(e)
}

/// Keep only well-formed plans: a parseable entitlement + a **unique** integer level. A
/// level shared by two plans drops all of them (ambiguous ordering must not silently
/// resolve); everything dropped is logged.
fn validate_plans(raw: Vec<PlanData>) -> Vec<CatalogPlan> {
    use std::collections::HashMap;
    // First keep only well-formed plans (parseable level + entitlement). A malformed
    // price must NOT participate in the duplicate-level count — otherwise it would poison
    // a valid plan that happens to share its `level`.
    let well_formed: Vec<CatalogPlan> = raw
        .into_iter()
        .filter_map(|p| {
            let (Some(level), Some(entitlement)) = (p.level, p.entitlement) else {
                tracing::warn!(price_id = %p.price_id, "plan dropped: missing level/entitlement metadata");
                return None;
            };
            Some(CatalogPlan {
                price_id: p.price_id,
                product_id: p.product_id,
                name: p.name,
                level,
                entitlement,
                amount_cents: p.amount_cents,
                currency: p.currency,
                interval: p.interval,
            })
        })
        .collect();
    // A `level` shared by two *well-formed* plans is genuinely ambiguous → drop all of them.
    let mut by_level: HashMap<u32, usize> = HashMap::new();
    for p in &well_formed {
        *by_level.entry(p.level).or_default() += 1;
    }
    well_formed
        .into_iter()
        .filter(|p| {
            let unique = by_level.get(&p.level).copied().unwrap_or(0) == 1;
            if !unique {
                tracing::warn!(price_id = %p.price_id, level = p.level, "plan dropped: duplicate level");
            }
            unique
        })
        .collect()
}

/// Keep only auto-applied promotions (the `wardnet_auto_apply` coupons).
fn validate_promos(raw: Vec<PromotionData>) -> Vec<CatalogPromo> {
    raw.into_iter()
        .filter(|c| c.auto_apply)
        .map(|c| CatalogPromo {
            coupon_id: c.coupon_id,
            name: c.name,
            percent_off: c.percent_off,
            amount_off: c.amount_off,
            currency: c.currency,
            applies_to_products: c.applies_to_products,
            start: c.start,
            redeem_by: c.redeem_by,
        })
        .collect()
}

#[cfg(test)]
mod tests;
