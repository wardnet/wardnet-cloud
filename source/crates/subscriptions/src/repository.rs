//! The **subscription** row — the provider-agnostic license that *grants* a
//! tenant's [`Entitlement`]. 1:N history with at most one live (non-`Canceled`) row
//! per tenant (the `uq_subscriptions_live` partial unique index); the free trial is
//! itself a subscription row. Owned by [`SubscriptionService`](crate::service);
//! **no other aggregate touches this table** — Billing reaches it only through the
//! [`SubscriptionCommands`](wardnet_common::ports::SubscriptionCommands) port.
//!
//! Payment-provider reference ids (Stripe customer/subscription/price) are **not**
//! here — they live in Billing's `billing_customers` table (ADR-0010).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::types::Json;

// `Entitlement` + `SubscriptionStatus` are part of the shared API contract; they
// double as the DB-domain types here (their helpers travel with them).
use wardnet_common::contract::SubscriptionView;
pub use wardnet_common::contract::{Entitlement, SubscriptionStatus};
use wardnet_common::db::DbPools;

/// A subscription row (license-only).
#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: String,
    pub tenant_id: String,
    pub status: SubscriptionStatus,
    pub entitlement: Entitlement,
    pub trial_expires_at: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Domain → contract conversion (orphan rule OK: `Subscription` is local here).
impl From<Subscription> for SubscriptionView {
    fn from(s: Subscription) -> Self {
        Self {
            id: s.id,
            status: s.status,
            entitlement: s.entitlement,
            trial_expires_at: s.trial_expires_at,
            current_period_end: s.current_period_end,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SubscriptionRow {
    id: String,
    tenant_id: String,
    status: String,
    entitlement: Json<Entitlement>,
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
            trial_expires_at: r.trial_expires_at,
            current_period_end: r.current_period_end,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

const SUBSCRIPTION_COLS: &str = "id, tenant_id, status, entitlement, \
     trial_expires_at, current_period_end, created_at, updated_at";

/// Insert the paid row. `convert_trial_to_paid` cancels the tenant's live trial first,
/// so on the normal path this is a plain insert. Under a concurrent conversion (two
/// racing checkout webhooks), the losing transaction's snapshot predates the winner's
/// paid row, so its cancel misses it and this insert would otherwise collide on
/// `uq_subscriptions_live`; the `ON CONFLICT` folds it into an in-place update of the
/// already-live row, keeping exactly one live row instead of erroring.
///
/// Semantics: this is **last-writer-wins** on the value columns (the winner's `id` /
/// `created_at` are kept). That is correct for the race it targets — the two racing
/// checkout webhooks carry the same freshly-created subscription state — but a concurrent
/// conversion is reconciled by commit order, not event order. It is only ever reached from
/// `apply_upsert`'s convert branch (current status trialing/none), so it can never
/// overwrite an existing *paid* row; a future caller that misrouted an update through this
/// path would be absorbed here rather than surfacing as a unique violation.
const INSERT_SUBSCRIPTION: &str = "INSERT INTO subscriptions \
     (id, tenant_id, status, entitlement, trial_expires_at, current_period_end, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
     ON CONFLICT (tenant_id) WHERE status <> 'canceled' DO UPDATE SET \
     status = EXCLUDED.status, entitlement = EXCLUDED.entitlement, \
     trial_expires_at = EXCLUDED.trial_expires_at, \
     current_period_end = EXCLUDED.current_period_end, updated_at = EXCLUDED.updated_at";

/// Data access for the `subscriptions` table (license columns only).
#[async_trait]
pub trait SubscriptionRepository: Send + Sync {
    /// Insert `sub` as the tenant's trial **iff the tenant has no subscription rows
    /// at all** — idempotent for a replayed `TenantCreated`, and it will **not**
    /// resurrect a trial for a tenant whose prior subscription was already canceled
    /// (that tenant has a row, so the insert is skipped). Returns `true` if inserted.
    async fn create_trial(&self, sub: &Subscription) -> anyhow::Result<bool>;

    /// The tenant's current (single non-`Canceled`) subscription, if any.
    async fn find_current(&self, tenant_id: &str) -> anyhow::Result<Option<Subscription>>;

    /// Convert: in one transaction, cancel the tenant's live row (the trial) and
    /// insert `paid` as the new live row. The cancel-before-insert order satisfies
    /// `uq_subscriptions_live`.
    async fn convert_trial_to_paid(
        &self,
        tenant_id: &str,
        paid: &Subscription,
    ) -> anyhow::Result<()>;

    /// Patch the tenant's live row to a provider update (status + entitlement +
    /// period). Returns `false` if the tenant has no live row.
    async fn update_current(
        &self,
        tenant_id: &str,
        status: SubscriptionStatus,
        entitlement: Entitlement,
        current_period_end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<bool>;

    /// Flag the tenant's live row `past_due`, preserving entitlement + period.
    /// Returns `false` if the tenant has no live row.
    async fn mark_past_due_current(&self, tenant_id: &str) -> anyhow::Result<bool>;

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

#[async_trait]
impl SubscriptionRepository for PgSubscriptionRepository {
    async fn create_trial(&self, sub: &Subscription) -> anyhow::Result<bool> {
        // INSERT … SELECT … WHERE NOT EXISTS: create the trial only when the tenant
        // has no subscription history at all (idempotent + never resurrects a reaped
        // trial). The `uq_subscriptions_live` index is a second guard against a race.
        let affected = sqlx::query(
            "INSERT INTO subscriptions \
             (id, tenant_id, status, entitlement, trial_expires_at, current_period_end, \
              created_at, updated_at) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8 \
             WHERE NOT EXISTS (SELECT 1 FROM subscriptions WHERE tenant_id = $2) \
             ON CONFLICT (tenant_id) WHERE status <> 'canceled' DO NOTHING",
        )
        .bind(&sub.id)
        .bind(&sub.tenant_id)
        .bind(sub.status.as_str())
        .bind(Json(sub.entitlement))
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
        let row = sqlx::query_as::<_, SubscriptionRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {SUBSCRIPTION_COLS} FROM subscriptions \
             WHERE tenant_id = $1 AND status <> 'canceled'"
        )))
        .bind(tenant_id)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(row.map(Into::into))
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
            .bind(paid.trial_expires_at)
            .bind(paid.current_period_end)
            .bind(paid.created_at)
            .bind(paid.updated_at)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn update_current(
        &self,
        tenant_id: &str,
        status: SubscriptionStatus,
        entitlement: Entitlement,
        current_period_end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            "UPDATE subscriptions \
             SET status = $2, entitlement = $3, current_period_end = $4, updated_at = now() \
             WHERE tenant_id = $1 AND status <> 'canceled'",
        )
        .bind(tenant_id)
        .bind(status.as_str())
        .bind(Json(entitlement))
        .bind(current_period_end)
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    async fn mark_past_due_current(&self, tenant_id: &str) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            "UPDATE subscriptions SET status = 'past_due', updated_at = now() \
             WHERE tenant_id = $1 AND status <> 'canceled'",
        )
        .bind(tenant_id)
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
}
