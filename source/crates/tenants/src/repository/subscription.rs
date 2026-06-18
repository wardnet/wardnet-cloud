//! The **subscription** — the billing aggregate that *grants* a tenant's
//! [`Entitlement`]. 1:N history with at most one live (non-`Canceled`) row per
//! tenant (the `uq_subscriptions_live` partial unique index); the free trial is
//! itself a subscription row. Owned by `SubscriptionService`; **no other service
//! touches this table**.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::types::Json;

// `Entitlement` + `SubscriptionStatus` are part of the shared API contract; they
// double as the DB-domain types here (their helpers travel with them).
pub use wardnet_common::contract::{Entitlement, SubscriptionStatus};

use crate::db::DbPools;

/// A subscription row.
#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: String,
    pub tenant_id: String,
    pub status: SubscriptionStatus,
    pub entitlement: Entitlement,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub price_id: Option<String>,
    pub trial_expires_at: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct SubscriptionRow {
    id: String,
    tenant_id: String,
    status: String,
    entitlement: Json<Entitlement>,
    stripe_customer_id: Option<String>,
    stripe_subscription_id: Option<String>,
    price_id: Option<String>,
    trial_expires_at: Option<DateTime<Utc>>,
    current_period_end: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<SubscriptionRow> for Subscription {
    fn from(r: SubscriptionRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            status: SubscriptionStatus::from_db(&r.status),
            entitlement: r.entitlement.0,
            stripe_customer_id: r.stripe_customer_id,
            stripe_subscription_id: r.stripe_subscription_id,
            price_id: r.price_id,
            trial_expires_at: r.trial_expires_at,
            current_period_end: r.current_period_end,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

const SUBSCRIPTION_COLS: &str = "id, tenant_id, status, entitlement, stripe_customer_id, \
     stripe_subscription_id, price_id, trial_expires_at, current_period_end, created_at, updated_at";

/// Data access for the `subscriptions` table + the Stripe-webhook idempotency ledger.
#[async_trait]
pub trait SubscriptionRepository: Send + Sync {
    /// Insert `sub` as the tenant's trial **iff the tenant has no subscription rows
    /// at all** — idempotent for a replayed `TenantCreated`, and it will **not**
    /// resurrect a trial for a tenant whose prior subscription was already canceled
    /// (that tenant has a row, so the insert is skipped). Returns `true` if inserted.
    async fn create_trial(&self, sub: &Subscription) -> anyhow::Result<bool>;

    /// The tenant's current (single non-`Canceled`) subscription, if any.
    async fn find_current(&self, tenant_id: &str) -> anyhow::Result<Option<Subscription>>;

    /// The subscription carrying `stripe_subscription_id`, if any (webhook lookup).
    async fn find_by_stripe_subscription_id(
        &self,
        stripe_subscription_id: &str,
    ) -> anyhow::Result<Option<Subscription>>;

    /// The most recent `stripe_customer_id` recorded for the tenant (across the whole
    /// history), so a re-subscribe reuses the same Stripe Customer.
    async fn latest_customer_id(&self, tenant_id: &str) -> anyhow::Result<Option<String>>;

    /// Stamp `stripe_customer_id` onto the tenant's live row (at checkout start).
    /// Returns `false` if the tenant has no live subscription.
    async fn stamp_customer_id(
        &self,
        tenant_id: &str,
        stripe_customer_id: &str,
    ) -> anyhow::Result<bool>;

    /// Convert: in one transaction, cancel the tenant's live row (the trial) and
    /// insert `paid` as the new live row. The cancel-before-insert order satisfies
    /// `uq_subscriptions_live`.
    async fn convert_trial_to_paid(
        &self,
        tenant_id: &str,
        paid: &Subscription,
    ) -> anyhow::Result<()>;

    /// Patch the row carrying `stripe_subscription_id` from a Stripe update. Returns
    /// `false` if no such row.
    async fn update_from_stripe(
        &self,
        stripe_subscription_id: &str,
        status: SubscriptionStatus,
        entitlement: Entitlement,
        current_period_end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<bool>;

    /// Cancel the tenant's current subscription. Returns `true` if one was canceled.
    async fn cancel_current(&self, tenant_id: &str) -> anyhow::Result<bool>;

    /// Tenant ids whose live subscription is overdue: a `trialing` row past
    /// `trial_cutoff` (= `now − trial_grace`) or a `past_due` row past
    /// `payment_cutoff` (= `now − payment_grace`).
    async fn list_overdue(
        &self,
        trial_cutoff: DateTime<Utc>,
        payment_cutoff: DateTime<Utc>,
    ) -> anyhow::Result<Vec<String>>;

    /// Record a processed Stripe event id. Returns `true` if newly recorded, `false`
    /// if it was already present (a redelivery to short-circuit).
    async fn record_event(&self, event_id: &str, now: DateTime<Utc>) -> anyhow::Result<bool>;
}

/// `PostgreSQL`-backed [`SubscriptionRepository`].
pub struct PgSubscriptionRepository {
    pools: DbPools,
}

impl PgSubscriptionRepository {
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            pools: DbPools::single(pool),
        }
    }

    #[must_use]
    pub fn new_pools(pools: DbPools) -> Self {
        Self { pools }
    }
}

const INSERT_SUBSCRIPTION: &str = "INSERT INTO subscriptions \
     (id, tenant_id, status, entitlement, stripe_customer_id, stripe_subscription_id, \
      price_id, trial_expires_at, current_period_end, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";

#[async_trait]
impl SubscriptionRepository for PgSubscriptionRepository {
    async fn create_trial(&self, sub: &Subscription) -> anyhow::Result<bool> {
        // INSERT … SELECT … WHERE NOT EXISTS: create the trial only when the tenant
        // has no subscription history at all (idempotent + never resurrects a reaped
        // trial). The `uq_subscriptions_live` index is a second guard against a race.
        let affected = sqlx::query(
            "INSERT INTO subscriptions \
             (id, tenant_id, status, entitlement, stripe_customer_id, stripe_subscription_id, \
              price_id, trial_expires_at, current_period_end, created_at, updated_at) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11 \
             WHERE NOT EXISTS (SELECT 1 FROM subscriptions WHERE tenant_id = $2) \
             ON CONFLICT (tenant_id) WHERE status <> 'canceled' DO NOTHING",
        )
        .bind(&sub.id)
        .bind(&sub.tenant_id)
        .bind(sub.status.as_str())
        .bind(Json(sub.entitlement))
        .bind(&sub.stripe_customer_id)
        .bind(&sub.stripe_subscription_id)
        .bind(&sub.price_id)
        .bind(sub.trial_expires_at)
        .bind(sub.current_period_end)
        .bind(sub.created_at)
        .bind(sub.updated_at)
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected == 1)
    }

    async fn find_current(&self, tenant_id: &str) -> anyhow::Result<Option<Subscription>> {
        let row = sqlx::query_as::<_, SubscriptionRow>(&format!(
            "SELECT {SUBSCRIPTION_COLS} FROM subscriptions \
             WHERE tenant_id = $1 AND status <> 'canceled'"
        ))
        .bind(tenant_id)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn find_by_stripe_subscription_id(
        &self,
        stripe_subscription_id: &str,
    ) -> anyhow::Result<Option<Subscription>> {
        let row = sqlx::query_as::<_, SubscriptionRow>(&format!(
            "SELECT {SUBSCRIPTION_COLS} FROM subscriptions WHERE stripe_subscription_id = $1"
        ))
        .bind(stripe_subscription_id)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn latest_customer_id(&self, tenant_id: &str) -> anyhow::Result<Option<String>> {
        let id: Option<String> = sqlx::query_scalar(
            "SELECT stripe_customer_id FROM subscriptions \
             WHERE tenant_id = $1 AND stripe_customer_id IS NOT NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(id)
    }

    async fn stamp_customer_id(
        &self,
        tenant_id: &str,
        stripe_customer_id: &str,
    ) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            "UPDATE subscriptions SET stripe_customer_id = $2, updated_at = now() \
             WHERE tenant_id = $1 AND status <> 'canceled'",
        )
        .bind(tenant_id)
        .bind(stripe_customer_id)
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    async fn convert_trial_to_paid(
        &self,
        tenant_id: &str,
        paid: &Subscription,
    ) -> anyhow::Result<()> {
        let mut tx = self.pools.write.begin().await?;
        // Cancel any live row first so the new paid row does not collide on
        // `uq_subscriptions_live`.
        sqlx::query(
            "UPDATE subscriptions SET status = 'canceled', updated_at = now() \
             WHERE tenant_id = $1 AND status <> 'canceled'",
        )
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(INSERT_SUBSCRIPTION)
            .bind(&paid.id)
            .bind(&paid.tenant_id)
            .bind(paid.status.as_str())
            .bind(Json(paid.entitlement))
            .bind(&paid.stripe_customer_id)
            .bind(&paid.stripe_subscription_id)
            .bind(&paid.price_id)
            .bind(paid.trial_expires_at)
            .bind(paid.current_period_end)
            .bind(paid.created_at)
            .bind(paid.updated_at)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn update_from_stripe(
        &self,
        stripe_subscription_id: &str,
        status: SubscriptionStatus,
        entitlement: Entitlement,
        current_period_end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            "UPDATE subscriptions \
             SET status = $2, entitlement = $3, current_period_end = $4, updated_at = now() \
             WHERE stripe_subscription_id = $1",
        )
        .bind(stripe_subscription_id)
        .bind(status.as_str())
        .bind(Json(entitlement))
        .bind(current_period_end)
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    async fn cancel_current(&self, tenant_id: &str) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            "UPDATE subscriptions SET status = 'canceled', updated_at = now() \
             WHERE tenant_id = $1 AND status <> 'canceled'",
        )
        .bind(tenant_id)
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    async fn list_overdue(
        &self,
        trial_cutoff: DateTime<Utc>,
        payment_cutoff: DateTime<Utc>,
    ) -> anyhow::Result<Vec<String>> {
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT tenant_id FROM subscriptions \
             WHERE (status = 'trialing' AND trial_expires_at < $1) \
                OR (status = 'past_due' AND current_period_end < $2)",
        )
        .bind(trial_cutoff)
        .bind(payment_cutoff)
        .fetch_all(&self.pools.read)
        .await?;
        Ok(ids)
    }

    async fn record_event(&self, event_id: &str, now: DateTime<Utc>) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            "INSERT INTO processed_stripe_events (event_id, processed_at) VALUES ($1, $2) \
             ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(event_id)
        .bind(now)
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected == 1)
    }
}
