-- Wardnet Tenants — global authority. Single fresh initialization (the DB is
-- empty; there is no prior schema to migrate from).
--
-- Domain:
--   tenant  (account: email, entitlement, subscription)
--     └─ network  (one wardnet network: vanity slug + provisioning lifecycle)
--          └─ daemon  (a device bound to the network; holds an Ed25519 key)
--
-- Plus two short-lived enrollment artifacts:
--   enrollment_codes      — the one-time, email-proving code (issued → burned at enroll)
--   pending_enrollments   — a TTL'd pubkey↔tenant binding letting a not-yet-registered
--                            daemon authenticate (mint a tenant-scoped JWT) before it has
--                            a network/daemon row. Self-cleaning by expiry.

CREATE TABLE tenants (
    id                  TEXT PRIMARY KEY,
    -- Stored lowercased so uniqueness is case-insensitive.
    email               VARCHAR(320) NOT NULL,
    -- Typed limits, e.g. {"max_networks":1,"max_daemons":1}. JSONB so new limit
    -- dimensions need no migration.
    entitlement         JSONB NOT NULL,
    subscription_status VARCHAR(16) NOT NULL DEFAULT 'active'
        CHECK (subscription_status IN ('active', 'canceled')),
    -- Provider-agnostic subscription handle (reserved; populated when billing lands).
    subscription_id     VARCHAR(255),
    created_at          TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_tenants_email UNIQUE (email)
);

CREATE TABLE networks (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The globally-unique vanity. This UNIQUE is the allocation lock.
    slug               VARCHAR(63) NOT NULL,
    display_name       VARCHAR(255) NOT NULL,
    -- Region that owns this network's DNS/tunnel; the regional DDNS provisioner
    -- filters its work queue by it.
    region             VARCHAR(63) NOT NULL,
    -- `deprovisioned` is NOT a stored state — it is the reaper's PATCH target that
    -- deletes the row (freeing the slug).
    provisioning_state VARCHAR(16) NOT NULL
        CHECK (provisioning_state IN ('provisioning', 'active', 'deprovisioning')),
    created_at         TIMESTAMPTZ NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_networks_slug UNIQUE (slug)
);
-- Supports the reaper/provisioner cursor scan:
--   WHERE provisioning_state = $1 AND region = $2 AND id > $cursor ORDER BY id.
CREATE INDEX idx_networks_state_region_id ON networks (provisioning_state, region, id);
CREATE INDEX idx_networks_tenant ON networks (tenant_id);

CREATE TABLE daemons (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    network_id  TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    -- Standard-base64 of the daemon's 32-byte Ed25519 public key (the `cnf` value).
    public_key  VARCHAR(64) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_daemons_public_key UNIQUE (public_key)
);
CREATE INDEX idx_daemons_tenant ON daemons (tenant_id);
CREATE INDEX idx_daemons_network ON daemons (network_id);

CREATE TABLE enrollment_codes (
    -- sha256 hex of the one-time code; the raw code is shown once and never stored.
    code_hash   VARCHAR(64) PRIMARY KEY,
    email       VARCHAR(320) NOT NULL,
    -- NULL = new-signup code (enroll creates the tenant); set = add-daemon code
    -- (tenant already exists).
    tenant_id   TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ
);

CREATE TABLE pending_enrollments (
    -- Standard-base64 of the enrolling daemon's Ed25519 public key.
    public_key  VARCHAR(64) PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_pending_enrollments_expires ON pending_enrollments (expires_at);

-- Per-IP rate limiting for the public new-signup code endpoint (anti-abuse).
CREATE TABLE enrollment_code_log (
    id          BIGSERIAL PRIMARY KEY,
    remote_ip   VARCHAR(45) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_enrollment_code_log_ip_time ON enrollment_code_log (remote_ip, created_at);
