-- The subscription is the provider-agnostic LICENSE (ADR-0010). Stripe reference
-- ids move OUT of `subscriptions` into the Billing-owned `billing_customers` table.
--
-- Forward-only + ordering: the billing `billing_customers` migration carries an
-- EARLIER timestamp, so its back-fill (INSERT … SELECT from subscriptions) has
-- already copied these columns before this migration drops them. `IF EXISTS` keeps
-- it safe on a fresh DB where init created the columns and on re-runs.
ALTER TABLE subscriptions
    DROP COLUMN IF EXISTS stripe_customer_id,
    DROP COLUMN IF EXISTS stripe_subscription_id,
    DROP COLUMN IF EXISTS price_id;

DROP INDEX IF EXISTS idx_subscriptions_stripe;
