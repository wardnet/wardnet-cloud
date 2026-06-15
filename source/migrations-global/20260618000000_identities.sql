-- Global Tenants identity authority — PostgreSQL (single global DB, shared across
-- the whole fleet). Replaces the former regional `installs` + global `names`
-- split: identity (id, vanity name, key, token) now lives in ONE global table, so
-- registration is a single global-DB transaction instead of a two-database saga.
--
-- identities — one row per registered install. `name` UNIQUE is the cross-region
--   vanity-slug allocation lock: an INSERT that violates it (SQLSTATE 23505) means
--   the name is taken. `token_hash` UNIQUE is the bearer-token index. `status`
--   carries the deregister tombstone (`active` → `deregistered`); 3a-ii deletes
--   the row on deregister, 3d flips status instead.
CREATE TABLE identities (
    id               VARCHAR(36) PRIMARY KEY,
    name             VARCHAR(64) NOT NULL,
    region           VARCHAR(32) NOT NULL,
    public_key       VARCHAR(64) NOT NULL,
    token_hash       VARCHAR(64) NOT NULL,
    status           VARCHAR(16) NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active', 'deregistered')),
    created_at       TIMESTAMPTZ NOT NULL,
    deregistered_at  TIMESTAMPTZ,
    CONSTRAINT uq_identities_name       UNIQUE (name),
    CONSTRAINT uq_identities_token_hash UNIQUE (token_hash)
);

-- registration_log — per-IP rate-limit table (3 registrations per IP per 24 h).
-- Moved here from the regional DB: registration is now a global (daemon→Tenants)
-- concern.
CREATE TABLE registration_log (
    id          BIGINT      GENERATED ALWAYS AS IDENTITY,
    remote_ip   VARCHAR(45) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_registration_log_ip_time ON registration_log (remote_ip, created_at);
