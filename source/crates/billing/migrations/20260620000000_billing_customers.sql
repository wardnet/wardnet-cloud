-- Billing-owned provider-reference table (ADR-0010): the payment-provider ids that
-- used to live on the `subscriptions` row move here, keyed by (tenant_id, provider).
-- One live row per (tenant, provider) holding the tenant's current refs.
--
-- Ordering: this migration carries an EARLIER timestamp than the subscriptions
-- `drop_stripe_cols` migration, so the back-fill below copies the columns BEFORE
-- they are dropped from `subscriptions`. The merged migrator runs them in timestamp
-- order against the single shared DB.
CREATE TABLE IF NOT EXISTS billing_customers (
    tenant_id              TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider               VARCHAR(32) NOT NULL DEFAULT 'stripe',
    stripe_customer_id     VARCHAR(255),
    stripe_subscription_id VARCHAR(255),
    price_id               VARCHAR(255),
    created_at             TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, provider)
);

-- Webhook → tenant lookup (and a guard for one subscription id per provider).
CREATE INDEX IF NOT EXISTS idx_billing_customers_subscription
    ON billing_customers (stripe_subscription_id);

-- Back-fill from existing subscription rows that carry provider refs. Per tenant,
-- prefer the **live** (non-canceled) subscription's refs — that is the row whose
-- stripe_subscription_id is still active — falling back to the most recent
-- stripe-bearing row only when no live row carries refs (so the tenant's stable
-- stripe_customer_id is still carried forward for re-subscribe).
INSERT INTO billing_customers
    (tenant_id, provider, stripe_customer_id, stripe_subscription_id, price_id, created_at, updated_at)
SELECT DISTINCT ON (s.tenant_id)
    s.tenant_id, 'stripe', s.stripe_customer_id, s.stripe_subscription_id, s.price_id,
    s.created_at, now()
FROM subscriptions s
WHERE s.stripe_customer_id IS NOT NULL
   OR s.stripe_subscription_id IS NOT NULL
ORDER BY s.tenant_id, (s.status = 'canceled'), s.created_at DESC
ON CONFLICT (tenant_id, provider) DO NOTHING;
