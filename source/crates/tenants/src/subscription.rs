//! `SubscriptionService` — owns **all** subscription/billing rules over the
//! subscription aggregate: opening the free trial, resolving the current
//! subscription, cancelling (with the network-deprovision cascade signalled by an
//! event), and expiring overdue trials / past-due subscriptions. The Stripe-driven
//! methods (`start_checkout` / `billing_portal` / `apply_stripe_event`) land with
//! the billing slice.
//!
//! It depends only on its own [`SubscriptionRepository`] and the
//! [`EventPublisher`] — **never** another aggregate's repository. Cross-aggregate
//! side-effects flow out as [`DomainEvent`]s for reactors to pick up.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use wardnet_common::event::{DomainEvent, EventPublisher};

use crate::error::SubscriptionError;
use crate::repository::SubscriptionRepository;
use crate::repository::subscription::{Entitlement, Subscription, SubscriptionStatus};
use crate::stripe::{StripeEvent, StripeEventKind, StripeGateway, SubscriptionData};

pub mod reactor;

/// Trial / grace policy, sourced from [`Config`](crate::config::Config).
#[derive(Debug, Clone, Copy)]
pub struct TrialPolicy {
    /// Free-trial length (days) applied at trial creation.
    pub trial_days: i64,
    /// Extra days a lapsed trial keeps service before the reaper cancels it.
    pub trial_grace_days: i64,
    /// Extra days a `past_due` subscription keeps service before the reaper cancels it.
    pub payment_grace_days: i64,
}

/// The subscription/billing business-rule layer.
pub struct SubscriptionService {
    subscriptions: Arc<dyn SubscriptionRepository>,
    events: Arc<dyn EventPublisher>,
    stripe: Arc<dyn StripeGateway>,
    policy: TrialPolicy,
}

impl SubscriptionService {
    #[must_use]
    pub fn new(
        subscriptions: Arc<dyn SubscriptionRepository>,
        events: Arc<dyn EventPublisher>,
        stripe: Arc<dyn StripeGateway>,
        policy: TrialPolicy,
    ) -> Self {
        Self {
            subscriptions,
            events,
            stripe,
            policy,
        }
    }

    /// Open the tenant's free **trial** subscription. Idempotent and safe to call
    /// for any tenant: the insert only lands when the tenant has *no* subscription
    /// history (so a replayed `TenantCreated` is a no-op, and a tenant whose trial
    /// already lapsed is never given a fresh one). Invoked by the subscription
    /// reactor on `TenantCreated`. Returns whether a trial was created.
    ///
    /// # Errors
    /// [`SubscriptionError::Internal`] on a repository failure.
    pub async fn create_trial(&self, tenant_id: &str) -> Result<bool, SubscriptionError> {
        let now = Utc::now();
        let sub = Subscription {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            status: SubscriptionStatus::Trialing,
            entitlement: Entitlement::DEFAULT,
            stripe_customer_id: None,
            stripe_subscription_id: None,
            price_id: None,
            trial_expires_at: Some(now + Duration::days(self.policy.trial_days)),
            current_period_end: None,
            created_at: now,
            updated_at: now,
        };
        let created = self.subscriptions.create_trial(&sub).await?;
        if created {
            tracing::info!(tenant_id, "opened trial subscription");
        }
        Ok(created)
    }

    /// The tenant's current (single non-`Canceled`) subscription, if any. The
    /// service-method read other services call instead of touching the repo.
    ///
    /// # Errors
    /// [`SubscriptionError::Internal`] on a repository failure.
    pub async fn current(
        &self,
        tenant_id: &str,
    ) -> Result<Option<Subscription>, SubscriptionError> {
        Ok(self.subscriptions.find_current(tenant_id).await?)
    }

    /// Cancel the tenant's current subscription and, if one was actually cancelled,
    /// publish [`DomainEvent::SubscriptionDeactivated`] so the network reactor
    /// deprovisions the tenant's networks. Idempotent — the single cancel path.
    ///
    /// # Errors
    /// [`SubscriptionError::Internal`] on a repository failure.
    pub async fn cancel(&self, tenant_id: &str) -> Result<(), SubscriptionError> {
        if self.subscriptions.cancel_current(tenant_id).await? {
            tracing::info!(tenant_id, "subscription cancelled");
            self.events.publish(DomainEvent::SubscriptionDeactivated {
                tenant_id: tenant_id.to_string(),
            });
        }
        Ok(())
    }

    /// Cancel every overdue subscription — a `trialing` row past
    /// `trial_expires_at + trial_grace`, or a `past_due` row past
    /// `current_period_end + payment_grace`. Each cancel cascades via its event.
    /// Driven by the periodic reaper loop. Returns the number cancelled.
    ///
    /// # Errors
    /// [`SubscriptionError::Internal`] on a repository failure.
    pub async fn expire_overdue(&self) -> Result<u64, SubscriptionError> {
        let now = Utc::now();
        let trial_cutoff = now - Duration::days(self.policy.trial_grace_days);
        let payment_cutoff = now - Duration::days(self.policy.payment_grace_days);
        let tenant_ids = self
            .subscriptions
            .list_overdue(trial_cutoff, payment_cutoff)
            .await?;
        let n = tenant_ids.len() as u64;
        for tenant_id in tenant_ids {
            self.cancel(&tenant_id).await?;
        }
        if n > 0 {
            tracing::info!(count = n, "expired overdue subscriptions");
        }
        Ok(n)
    }

    /// Whether `sub` currently entitles its tenant to service, accounting for the
    /// trial / payment grace windows. The config-aware check `mint_jwt` uses (the
    /// wire [`SubscriptionView`](wardnet_common::contract::SubscriptionView) embeds a
    /// grace-free predicate for consumers that lack the policy).
    #[must_use]
    pub fn is_active(&self, sub: &Subscription, now: DateTime<Utc>) -> bool {
        match sub.status {
            SubscriptionStatus::Active => true,
            SubscriptionStatus::Trialing => sub
                .trial_expires_at
                .is_some_and(|t| now < t + Duration::days(self.policy.trial_grace_days)),
            SubscriptionStatus::PastDue => sub
                .current_period_end
                .is_some_and(|c| now < c + Duration::days(self.policy.payment_grace_days)),
            SubscriptionStatus::Canceled => false,
        }
    }

    // ── Stripe billing ───────────────────────────────────────────────────────────

    /// Start a Stripe Checkout for `price_id`, reusing the tenant's existing Stripe
    /// Customer when known. Returns the URL to redirect the user to. The
    /// subscription itself is recorded later, by the `customer.subscription.created`
    /// webhook.
    ///
    /// # Errors
    /// [`SubscriptionError::Internal`] on a Stripe/repository failure.
    pub async fn start_checkout(
        &self,
        tenant_id: &str,
        email: &str,
        price_id: &str,
    ) -> Result<String, SubscriptionError> {
        let customer_id = self.subscriptions.latest_customer_id(tenant_id).await?;
        let session = self
            .stripe
            .create_checkout_session(customer_id.as_deref(), email, price_id, tenant_id)
            .await
            .map_err(SubscriptionError::Internal)?;
        // Best-effort: stamp the customer id onto the live row if Stripe surfaced one
        // now (the authoritative value still arrives via the webhook).
        if let Some(cid) = session.customer_id {
            self.subscriptions
                .stamp_customer_id(tenant_id, &cid)
                .await?;
        }
        Ok(session.url)
    }

    /// Create a Stripe Billing Portal session for the tenant's Customer.
    ///
    /// # Errors
    /// [`SubscriptionError::BadRequest`] if the tenant has no Stripe Customer yet;
    /// [`SubscriptionError::Internal`] on a Stripe failure.
    pub async fn billing_portal(&self, tenant_id: &str) -> Result<String, SubscriptionError> {
        let customer_id = self
            .subscriptions
            .latest_customer_id(tenant_id)
            .await?
            .ok_or_else(|| {
                SubscriptionError::BadRequest("tenant has no billing account yet".to_string())
            })?;
        self.stripe
            .create_billing_portal_session(&customer_id)
            .await
            .map_err(SubscriptionError::Internal)
    }

    /// Verify a raw Stripe webhook (the signature is the credential) and apply it.
    /// A bad signature is a [`SubscriptionError::BadRequest`] (the endpoint returns
    /// `400`); a verified event is applied idempotently.
    ///
    /// # Errors
    /// [`SubscriptionError::BadRequest`] on an unverifiable/malformed payload;
    /// [`SubscriptionError::Internal`] on a repository failure.
    pub async fn handle_webhook(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> Result<(), SubscriptionError> {
        let event = self
            .stripe
            .construct_event(payload, signature)
            .map_err(|e| SubscriptionError::BadRequest(format!("invalid Stripe webhook: {e}")))?;
        self.apply_stripe_event(event).await
    }

    /// Apply a verified Stripe webhook event, idempotently (a redelivery whose id is
    /// already recorded is a no-op). Drives trial→paid conversion, plan changes,
    /// cancellation, and payment-failure transitions.
    ///
    /// # Errors
    /// [`SubscriptionError::Internal`] on a repository failure.
    pub async fn apply_stripe_event(&self, event: StripeEvent) -> Result<(), SubscriptionError> {
        // Fast-path dedupe. The id is recorded only AFTER a successful apply (below),
        // so a failed apply stays un-recorded and Stripe's retry re-applies it — the
        // ledger must never mark an event done before its effect lands.
        if self.subscriptions.is_event_processed(&event.id).await? {
            tracing::debug!(event_id = %event.id, "stripe event already processed; skipping");
            return Ok(());
        }
        self.apply_event_kind(event.kind).await?;
        self.subscriptions
            .record_event(&event.id, Utc::now())
            .await?;
        Ok(())
    }

    /// Apply the event's effect. Each branch is idempotent, so an at-least-once
    /// redelivery (or a retry after a recorded-but-failed apply) is safe.
    async fn apply_event_kind(&self, kind: StripeEventKind) -> Result<(), SubscriptionError> {
        match kind {
            StripeEventKind::SubscriptionUpsert(data) => self.apply_upsert(data).await?,
            StripeEventKind::SubscriptionDeleted {
                stripe_subscription_id,
            } => {
                if let Some(sub) = self
                    .subscriptions
                    .find_by_stripe_subscription_id(&stripe_subscription_id)
                    .await?
                {
                    self.cancel(&sub.tenant_id).await?;
                }
            }
            StripeEventKind::PaymentFailed {
                stripe_subscription_id,
            } => {
                if let Some(sub) = self
                    .subscriptions
                    .find_by_stripe_subscription_id(&stripe_subscription_id)
                    .await?
                {
                    self.subscriptions
                        .update_from_stripe(
                            &stripe_subscription_id,
                            SubscriptionStatus::PastDue,
                            sub.entitlement,
                            sub.current_period_end,
                        )
                        .await?;
                }
            }
            StripeEventKind::Ignored => {}
        }
        Ok(())
    }

    /// `customer.subscription.created`/`.updated`: reconcile our row to Stripe's state.
    async fn apply_upsert(&self, data: SubscriptionData) -> Result<(), SubscriptionError> {
        if let Some(existing) = self
            .subscriptions
            .find_by_stripe_subscription_id(&data.stripe_subscription_id)
            .await?
        {
            if data.status == SubscriptionStatus::Canceled {
                // Route cancellation through `cancel` so it publishes the deactivation.
                self.cancel(&existing.tenant_id).await?;
            } else {
                let entitlement = data.entitlement.unwrap_or(existing.entitlement);
                self.subscriptions
                    .update_from_stripe(
                        &data.stripe_subscription_id,
                        data.status,
                        entitlement,
                        data.current_period_end,
                    )
                    .await?;
            }
            return Ok(());
        }

        // A brand-new paid subscription. We need the tenant (from metadata) and the
        // plan's entitlement; without either we decline to grant (safe-closed).
        if data.status == SubscriptionStatus::Canceled {
            return Ok(());
        }
        let Some(tenant_id) = data.tenant_id else {
            tracing::error!(
                stripe_subscription_id = %data.stripe_subscription_id,
                "stripe subscription has no tenant_id metadata; ignoring"
            );
            return Ok(());
        };
        let Some(entitlement) = data.entitlement else {
            tracing::error!(
                stripe_subscription_id = %data.stripe_subscription_id,
                "stripe price has no max_networks/max_daemons metadata; not granting"
            );
            return Ok(());
        };
        let now = Utc::now();
        let paid = Subscription {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            status: data.status,
            entitlement,
            stripe_customer_id: Some(data.stripe_customer_id),
            stripe_subscription_id: Some(data.stripe_subscription_id),
            price_id: data.price_id,
            trial_expires_at: None,
            current_period_end: data.current_period_end,
            created_at: now,
            updated_at: now,
        };
        self.subscriptions
            .convert_trial_to_paid(&tenant_id, &paid)
            .await?;
        tracing::info!(tenant_id, "converted to paid subscription");
        Ok(())
    }
}

#[cfg(test)]
mod tests;
