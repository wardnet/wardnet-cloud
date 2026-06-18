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
    policy: TrialPolicy,
}

impl SubscriptionService {
    #[must_use]
    pub fn new(
        subscriptions: Arc<dyn SubscriptionRepository>,
        events: Arc<dyn EventPublisher>,
        policy: TrialPolicy,
    ) -> Self {
        Self {
            subscriptions,
            events,
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
}

#[cfg(test)]
mod tests;
