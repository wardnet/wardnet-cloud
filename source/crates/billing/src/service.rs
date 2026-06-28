//! `BillingService` — owns *how a subscription is paid for*: hosted Checkout/Portal,
//! the Stripe webhook, the provider-reference table, and the idempotency ledger.
//!
//! It drives the **license** aggregate exclusively through the
//! [`SubscriptionReader`] / [`SubscriptionCommands`] ports — it never names a
//! `subscriptions` (or `tenants`) type, so the boundary is compiler-enforced
//! (ADR-0010). Subscription never calls Billing back.

use std::sync::Arc;

use chrono::Utc;

use wardnet_common::contract::{Entitlement, SubscriptionStatus};
use wardnet_common::ports::{BillingError, BillingPort, SubscriptionCommands, SubscriptionReader};

use crate::gateway::{StripeEvent, StripeEventKind, StripeGateway, SubscriptionData};
use crate::repository::BillingRepository;

/// The payment business-rule layer.
pub struct BillingService {
    stripe: Arc<dyn StripeGateway>,
    billing: Arc<dyn BillingRepository>,
    /// Read the license aggregate (e.g. preserve entitlement on a provider update
    /// that carries no price metadata).
    subscription_reader: Arc<dyn SubscriptionReader>,
    /// The one-way Billing → Subscription write edge.
    subscription_commands: Arc<dyn SubscriptionCommands>,
}

impl BillingService {
    #[must_use]
    pub fn new(
        stripe: Arc<dyn StripeGateway>,
        billing: Arc<dyn BillingRepository>,
        subscription_reader: Arc<dyn SubscriptionReader>,
        subscription_commands: Arc<dyn SubscriptionCommands>,
    ) -> Self {
        Self {
            stripe,
            billing,
            subscription_reader,
            subscription_commands,
        }
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
    ) -> Result<String, BillingError> {
        let customer_id = self.billing.customer_id(tenant_id).await?;
        let session = self
            .stripe
            .create_checkout_session(customer_id.as_deref(), email, price_id, tenant_id)
            .await
            .map_err(BillingError::Internal)?;
        // Best-effort: stamp the customer id now if Stripe surfaced one (the
        // authoritative value still arrives via the webhook).
        if let Some(cid) = session.customer_id {
            self.billing.upsert_customer(tenant_id, &cid).await?;
        }
        Ok(session.url)
    }

    async fn billing_portal(&self, tenant_id: &str) -> Result<String, BillingError> {
        let customer_id = self.billing.customer_id(tenant_id).await?.ok_or_else(|| {
            BillingError::InvalidRequest("tenant has no billing account yet".to_string())
        })?;
        self.stripe
            .create_billing_portal_session(&customer_id)
            .await
            .map_err(BillingError::Internal)
    }

    async fn handle_webhook(&self, payload: &[u8], signature: &str) -> Result<(), BillingError> {
        let event = self
            .stripe
            .construct_event(payload, signature)
            .map_err(|e| BillingError::InvalidRequest(format!("invalid Stripe webhook: {e}")))?;
        self.apply_event(event).await
    }
}
