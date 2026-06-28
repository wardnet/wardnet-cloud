//! Billing data access: the **`billing_customers`** provider-reference table (the
//! tenant's payment-provider ids — Stripe customer/subscription/price) and the
//! **`processed_stripe_events`** webhook idempotency ledger. Both are owned by the
//! Billing aggregate; no other aggregate touches them (ADR-0010).

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use wardnet_common::db::DbPools;

/// The payment provider behind a tenant's billing account. One value today; the
/// column keeps the table provider-neutral for later.
pub const PROVIDER_STRIPE: &str = "stripe";

/// Data access for the Billing-owned tables.
#[async_trait]
pub trait BillingRepository: Send + Sync {
    /// Stamp the tenant's provider **customer** id (at checkout start), inserting the
    /// `billing_customers` row if absent. Idempotent.
    async fn upsert_customer(
        &self,
        tenant_id: &str,
        stripe_customer_id: &str,
    ) -> anyhow::Result<()>;

    /// Record the tenant's current provider **subscription** (customer + subscription
    /// + price ids), inserting or updating the `billing_customers` row. Idempotent.
    async fn upsert_subscription(
        &self,
        tenant_id: &str,
        stripe_customer_id: &str,
        stripe_subscription_id: &str,
        price_id: Option<&str>,
    ) -> anyhow::Result<()>;

    /// The tenant's recorded provider customer id, if any (so a re-subscribe reuses
    /// the same Stripe Customer, and the portal can be opened).
    async fn customer_id(&self, tenant_id: &str) -> anyhow::Result<Option<String>>;

    /// The tenant that owns `stripe_subscription_id`, if any (webhook → tenant lookup).
    async fn tenant_for_subscription(
        &self,
        stripe_subscription_id: &str,
    ) -> anyhow::Result<Option<String>>;

    /// Whether a Stripe event id has already been processed (the fast-path dedupe
    /// read). Checked **before** applying; the id is recorded only **after** a
    /// successful apply, so a failed apply leaves it un-recorded and Stripe's retry
    /// re-applies it.
    async fn is_event_processed(&self, event_id: &str) -> anyhow::Result<bool>;

    /// Record a processed Stripe event id (after a successful apply). Idempotent.
    async fn record_event(&self, event_id: &str, now: DateTime<Utc>) -> anyhow::Result<()>;
}

/// `PostgreSQL`-backed [`BillingRepository`].
pub struct PgBillingRepository {
    pools: DbPools,
}

impl PgBillingRepository {
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
impl BillingRepository for PgBillingRepository {
    async fn upsert_customer(
        &self,
        tenant_id: &str,
        stripe_customer_id: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO billing_customers \
             (tenant_id, provider, stripe_customer_id, created_at, updated_at) \
             VALUES ($1, $2, $3, now(), now()) \
             ON CONFLICT (tenant_id, provider) \
             DO UPDATE SET stripe_customer_id = EXCLUDED.stripe_customer_id, updated_at = now()",
        )
        .bind(tenant_id)
        .bind(PROVIDER_STRIPE)
        .bind(stripe_customer_id)
        .execute(&self.pools.write)
        .await?;
        Ok(())
    }

    async fn upsert_subscription(
        &self,
        tenant_id: &str,
        stripe_customer_id: &str,
        stripe_subscription_id: &str,
        price_id: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO billing_customers \
             (tenant_id, provider, stripe_customer_id, stripe_subscription_id, price_id, \
              created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, now(), now()) \
             ON CONFLICT (tenant_id, provider) DO UPDATE SET \
                 stripe_customer_id = EXCLUDED.stripe_customer_id, \
                 stripe_subscription_id = EXCLUDED.stripe_subscription_id, \
                 price_id = EXCLUDED.price_id, \
                 updated_at = now()",
        )
        .bind(tenant_id)
        .bind(PROVIDER_STRIPE)
        .bind(stripe_customer_id)
        .bind(stripe_subscription_id)
        .bind(price_id)
        .execute(&self.pools.write)
        .await?;
        Ok(())
    }

    async fn customer_id(&self, tenant_id: &str) -> anyhow::Result<Option<String>> {
        let id: Option<String> = sqlx::query_scalar(
            "SELECT stripe_customer_id FROM billing_customers \
             WHERE tenant_id = $1 AND provider = $2 AND stripe_customer_id IS NOT NULL",
        )
        .bind(tenant_id)
        .bind(PROVIDER_STRIPE)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(id)
    }

    async fn tenant_for_subscription(
        &self,
        stripe_subscription_id: &str,
    ) -> anyhow::Result<Option<String>> {
        let tenant_id: Option<String> = sqlx::query_scalar(
            "SELECT tenant_id FROM billing_customers \
             WHERE stripe_subscription_id = $1 AND provider = $2",
        )
        .bind(stripe_subscription_id)
        .bind(PROVIDER_STRIPE)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(tenant_id)
    }

    async fn is_event_processed(&self, event_id: &str) -> anyhow::Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM processed_stripe_events WHERE event_id = $1)",
        )
        .bind(event_id)
        .fetch_one(&self.pools.read)
        .await?;
        Ok(exists)
    }

    async fn record_event(&self, event_id: &str, now: DateTime<Utc>) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO processed_stripe_events (event_id, processed_at) VALUES ($1, $2) \
             ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(event_id)
        .bind(now)
        .execute(&self.pools.write)
        .await?;
        Ok(())
    }
}
