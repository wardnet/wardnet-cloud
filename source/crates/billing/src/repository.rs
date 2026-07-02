//! Billing data access: the **`billing_customers`** provider-reference table (the
//! tenant's payment-provider ids — Stripe customer/subscription/price) and the
//! **`processed_stripe_events`** webhook idempotency ledger. Both are owned by the
//! Billing aggregate; no other aggregate touches them (ADR-0010).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;

use wardnet_common::contract::Entitlement;
use wardnet_common::db::DbPools;

/// The payment provider behind a tenant's billing account. One value today; the
/// column keeps the table provider-neutral for later.
pub const PROVIDER_STRIPE: &str = "stripe";

/// A tenant's recorded provider references (read for the change-plan / account-page path).
#[derive(Debug, Clone, Default)]
pub struct BillingRef {
    pub customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub price_id: Option<String>,
}

/// One validated plan in the catalog projection (entitlement + level already parsed).
#[derive(Debug, Clone)]
pub struct CatalogPlan {
    pub price_id: String,
    pub product_id: String,
    pub name: String,
    pub level: u32,
    pub entitlement: Entitlement,
    pub amount_cents: i64,
    pub currency: String,
    pub interval: String,
}

/// One auto-applied promotion in the catalog projection.
#[derive(Debug, Clone)]
pub struct CatalogPromo {
    pub coupon_id: String,
    pub name: String,
    pub percent_off: Option<f64>,
    pub amount_off: Option<i64>,
    pub currency: Option<String>,
    pub applies_to_products: Vec<String>,
    pub start: Option<DateTime<Utc>>,
    pub redeem_by: Option<DateTime<Utc>>,
}

/// The whole catalog projection plus the last-sync stamp (for the staleness guard).
#[derive(Debug, Clone, Default)]
pub struct CatalogSnapshot {
    pub plans: Vec<CatalogPlan>,
    pub promos: Vec<CatalogPromo>,
    /// `None` when the worker has never synced (the catalog has no rows yet).
    pub last_synced_at: Option<DateTime<Utc>>,
}

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
    /// the same Stripe Customer, and a card update can be started).
    async fn customer_id(&self, tenant_id: &str) -> anyhow::Result<Option<String>>;

    /// The tenant's full recorded provider references (customer + subscription + price),
    /// or `None` if it has no `billing_customers` row. Drives change-plan (current price →
    /// level) and the account-page billing subscription read.
    async fn billing_ref(&self, tenant_id: &str) -> anyhow::Result<Option<BillingRef>>;

    /// Replace the entire catalog projection (plans + promotions) and stamp the sync
    /// time, atomically. The worker is the sole writer, so a full replace keeps the
    /// projection an exact mirror of the last Stripe list (dropped plans/promos vanish).
    async fn replace_catalog(
        &self,
        plans: &[CatalogPlan],
        promos: &[CatalogPromo],
        now: DateTime<Utc>,
    ) -> anyhow::Result<()>;

    /// Read the whole catalog projection + last-sync stamp (for `GET /v1/plans` and
    /// server-side promo derivation).
    async fn read_catalog(&self) -> anyhow::Result<CatalogSnapshot>;

    /// The tenant that owns `stripe_subscription_id`, if any (webhook → tenant lookup).
    async fn tenant_for_subscription(
        &self,
        stripe_subscription_id: &str,
    ) -> anyhow::Result<Option<String>>;

    /// The subscription id recorded for a provider `stripe_customer_id`, if any (used by
    /// the setup-completion webhook to set the new card as the subscription's default).
    async fn subscription_for_customer(
        &self,
        stripe_customer_id: &str,
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

    async fn billing_ref(&self, tenant_id: &str) -> anyhow::Result<Option<BillingRef>> {
        let row = sqlx::query(
            "SELECT stripe_customer_id, stripe_subscription_id, price_id \
             FROM billing_customers WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(tenant_id)
        .bind(PROVIDER_STRIPE)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(row
            .map(|r| -> anyhow::Result<BillingRef> {
                Ok(BillingRef {
                    customer_id: r.try_get("stripe_customer_id")?,
                    stripe_subscription_id: r.try_get("stripe_subscription_id")?,
                    price_id: r.try_get("price_id")?,
                })
            })
            .transpose()?)
    }

    async fn replace_catalog(
        &self,
        plans: &[CatalogPlan],
        promos: &[CatalogPromo],
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut tx = self.pools.write.begin().await?;
        sqlx::query("DELETE FROM billing_catalog")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM billing_promotions")
            .execute(&mut *tx)
            .await?;
        for p in plans {
            sqlx::query(
                "INSERT INTO billing_catalog \
                 (price_id, product_id, name, level, max_networks, max_daemons, \
                  amount_cents, currency, interval) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(&p.price_id)
            .bind(&p.product_id)
            .bind(&p.name)
            .bind(i32::try_from(p.level)?)
            .bind(i32::try_from(p.entitlement.max_networks)?)
            .bind(i32::try_from(p.entitlement.max_daemons)?)
            .bind(p.amount_cents)
            .bind(&p.currency)
            .bind(&p.interval)
            .execute(&mut *tx)
            .await?;
        }
        for c in promos {
            sqlx::query(
                "INSERT INTO billing_promotions \
                 (coupon_id, name, percent_off, amount_off, currency, \
                  applies_to_products, promo_start, redeem_by) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&c.coupon_id)
            .bind(&c.name)
            .bind(c.percent_off)
            .bind(c.amount_off)
            .bind(&c.currency)
            .bind(&c.applies_to_products)
            .bind(c.start)
            .bind(c.redeem_by)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "INSERT INTO billing_catalog_meta (id, last_synced_at) VALUES (TRUE, $1) \
             ON CONFLICT (id) DO UPDATE SET last_synced_at = EXCLUDED.last_synced_at",
        )
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn read_catalog(&self) -> anyhow::Result<CatalogSnapshot> {
        let plan_rows = sqlx::query(
            "SELECT price_id, product_id, name, level, max_networks, max_daemons, \
             amount_cents, currency, interval FROM billing_catalog ORDER BY level",
        )
        .fetch_all(&self.pools.read)
        .await?;
        let mut plans = Vec::with_capacity(plan_rows.len());
        for r in plan_rows {
            plans.push(CatalogPlan {
                price_id: r.try_get("price_id")?,
                product_id: r.try_get("product_id")?,
                name: r.try_get("name")?,
                level: u32::try_from(r.try_get::<i32, _>("level")?)?,
                entitlement: Entitlement {
                    max_networks: u32::try_from(r.try_get::<i32, _>("max_networks")?)?,
                    max_daemons: u32::try_from(r.try_get::<i32, _>("max_daemons")?)?,
                },
                amount_cents: r.try_get("amount_cents")?,
                currency: r.try_get("currency")?,
                interval: r.try_get("interval")?,
            });
        }
        let promo_rows = sqlx::query(
            "SELECT coupon_id, name, percent_off, amount_off, currency, \
             applies_to_products, promo_start, redeem_by FROM billing_promotions",
        )
        .fetch_all(&self.pools.read)
        .await?;
        let mut promos = Vec::with_capacity(promo_rows.len());
        for r in promo_rows {
            promos.push(CatalogPromo {
                coupon_id: r.try_get("coupon_id")?,
                name: r.try_get("name")?,
                percent_off: r.try_get("percent_off")?,
                amount_off: r.try_get("amount_off")?,
                currency: r.try_get("currency")?,
                applies_to_products: r.try_get("applies_to_products")?,
                start: r.try_get("promo_start")?,
                redeem_by: r.try_get("redeem_by")?,
            });
        }
        let last_synced_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT last_synced_at FROM billing_catalog_meta WHERE id = TRUE")
                .fetch_optional(&self.pools.read)
                .await?;
        Ok(CatalogSnapshot {
            plans,
            promos,
            last_synced_at,
        })
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

    async fn subscription_for_customer(
        &self,
        stripe_customer_id: &str,
    ) -> anyhow::Result<Option<String>> {
        // The row may exist with a NULL subscription (customer recorded pre-subscription),
        // so the scalar is itself nullable → `Option<Option<String>>`.
        let sub: Option<Option<String>> = sqlx::query_scalar(
            "SELECT stripe_subscription_id FROM billing_customers \
             WHERE stripe_customer_id = $1 AND provider = $2",
        )
        .bind(stripe_customer_id)
        .bind(PROVIDER_STRIPE)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(sub.flatten())
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
