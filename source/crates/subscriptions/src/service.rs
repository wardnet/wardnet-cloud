//! `SubscriptionService` — owns the **license** rules over the subscription
//! aggregate: opening the free trial, resolving the current subscription, cancelling
//! (with the network-deprovision cascade signalled by an event), expiring overdue
//! trials / past-due subscriptions, and the grace-aware entitlement check.
//!
//! It depends only on its own [`SubscriptionRepository`] and the
//! [`EventBus`] — **never** another aggregate's repository, and **never** a payment
//! provider. Cross-aggregate side-effects flow out as [`DomainEvent`]s; the inbound
//! Billing → Subscription edge arrives through the
//! [`SubscriptionCommands`] port impl below.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use wardnet_common::contract::{Entitlement, SubscriptionStatus, SubscriptionView};
use wardnet_common::event::{DomainEvent, EventBus};
use wardnet_common::ports::{SubscriptionCommands, SubscriptionReader};

use crate::error::SubscriptionError;
use crate::repository::{Subscription, SubscriptionRepository};

/// Trial / grace policy, sourced from the service config.
#[derive(Debug, Clone, Copy)]
pub struct TrialPolicy {
    /// Free-trial length (days) applied at trial creation.
    pub trial_days: i64,
    /// Extra days a lapsed trial keeps service before the reaper cancels it.
    pub trial_grace_days: i64,
    /// Extra days a `past_due` subscription keeps service before the reaper cancels it.
    pub payment_grace_days: i64,
}

/// The license business-rule layer.
pub struct SubscriptionService {
    subscriptions: Arc<dyn SubscriptionRepository>,
    events: Arc<dyn EventBus>,
    policy: TrialPolicy,
}

impl SubscriptionService {
    #[must_use]
    pub fn new(
        subscriptions: Arc<dyn SubscriptionRepository>,
        events: Arc<dyn EventBus>,
        policy: TrialPolicy,
    ) -> Self {
        Self {
            subscriptions,
            events,
            policy,
        }
    }

    /// Open the tenant's free **trial** subscription. Idempotent and safe to call for
    /// any tenant: the insert only lands when the tenant has *no* subscription history
    /// (so a replayed `TenantCreated` is a no-op, and a tenant whose trial already
    /// lapsed is never given a fresh one). Returns whether a trial was created.
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

    /// The tenant's current (single non-`Canceled`) subscription, if any.
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
            // Best-effort publish: the cancel is already committed, so a transport
            // failure must not fail the call — the network reactor's deprovision is
            // re-driven by the periodic reconcile (ADR-0007/0010).
            let event = DomainEvent::SubscriptionDeactivated {
                tenant_id: tenant_id.to_string(),
            };
            if let Err(e) = self.events.publish(&event).await {
                tracing::error!(error = %e, tenant_id, "failed to publish SubscriptionDeactivated; reconcile is the safety net");
            }
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
    /// trial / payment grace windows. The grace-aware check `mint_jwt` and
    /// `register_network` use via the [`SubscriptionReader`] port.
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

// ── Inter-aggregate ports (in-process adapter = direct calls) ────────────────────

#[async_trait]
impl SubscriptionReader for SubscriptionService {
    async fn current(&self, tenant_id: &str) -> anyhow::Result<Option<SubscriptionView>> {
        Ok(self
            .subscriptions
            .find_current(tenant_id)
            .await?
            .map(Into::into))
    }

    async fn is_active(&self, tenant_id: &str) -> anyhow::Result<bool> {
        let now = Utc::now();
        Ok(self
            .subscriptions
            .find_current(tenant_id)
            .await?
            .is_some_and(|sub| SubscriptionService::is_active(self, &sub, now)))
    }
}

#[async_trait]
impl SubscriptionCommands for SubscriptionService {
    async fn convert_trial_to_paid(
        &self,
        tenant_id: &str,
        status: SubscriptionStatus,
        entitlement: Entitlement,
        current_period_end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        let paid = Subscription {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            // Carry the provider-reported status (Active / PastDue), not a hardcoded
            // Active — a past-due initial subscription must not be granted full service.
            status,
            entitlement,
            trial_expires_at: None,
            current_period_end,
            created_at: now,
            updated_at: now,
        };
        self.subscriptions
            .convert_trial_to_paid(tenant_id, &paid)
            .await?;
        tracing::info!(tenant_id, "converted to paid subscription");
        Ok(())
    }

    async fn update_paid(
        &self,
        tenant_id: &str,
        status: SubscriptionStatus,
        entitlement: Entitlement,
        current_period_end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<bool> {
        Ok(self
            .subscriptions
            .update_current(tenant_id, status, entitlement, current_period_end)
            .await?)
    }

    async fn mark_past_due(&self, tenant_id: &str) -> anyhow::Result<bool> {
        Ok(self.subscriptions.mark_past_due_current(tenant_id).await?)
    }

    async fn cancel(&self, tenant_id: &str) -> anyhow::Result<()> {
        // The inherent `cancel` (publishes SubscriptionDeactivated) is the single
        // cancel path; the port just exposes it across the crate boundary.
        SubscriptionService::cancel(self, tenant_id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
