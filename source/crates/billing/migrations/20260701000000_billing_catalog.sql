-- The plan-catalog projection: a Billing-owned read-model the catalog-sync worker keeps
-- in sync with Stripe (the source of truth). `GET /v1/plans` and server-side promo
-- derivation read these tables, never Stripe on the hot path (ADR-0011). The worker is
-- the *only* writer; it replaces the whole (small) catalog each sync, so these tables are
-- a cache, not authority.

-- One row per purchasable plan (a validated Stripe recurring Price). Only plans with a
-- parseable entitlement + a unique integer level reach this table (safe-closed filtering
-- happens in the worker).
CREATE TABLE IF NOT EXISTS billing_catalog (
    price_id     VARCHAR(255) PRIMARY KEY,
    product_id   VARCHAR(255) NOT NULL,
    name         TEXT         NOT NULL,
    level        INTEGER      NOT NULL,
    max_networks INTEGER      NOT NULL,
    max_daemons  INTEGER      NOT NULL,
    amount_cents BIGINT       NOT NULL,
    currency     TEXT         NOT NULL,
    interval     TEXT         NOT NULL
);

-- One row per auto-applied promotion (a Stripe coupon flagged `wardnet_auto_apply`). The
-- active window is `[promo_start, redeem_by]`; live-ness is evaluated against the clock at
-- request time, so a stale projection never shows an expired promo.
CREATE TABLE IF NOT EXISTS billing_promotions (
    coupon_id           VARCHAR(255) PRIMARY KEY,
    name                TEXT        NOT NULL,
    percent_off         DOUBLE PRECISION,
    amount_off          BIGINT,
    currency            TEXT,
    applies_to_products TEXT[]      NOT NULL DEFAULT '{}',
    promo_start         TIMESTAMPTZ,
    redeem_by           TIMESTAMPTZ
);

-- A single-row stamp of the last successful sync, for the hard staleness guard: a catalog
-- older than the configured bound is refused (503) rather than served as ancient pricing.
CREATE TABLE IF NOT EXISTS billing_catalog_meta (
    id             BOOLEAN     PRIMARY KEY DEFAULT TRUE,
    last_synced_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT billing_catalog_meta_singleton CHECK (id)
);
