-- WS-F: human/web authentication (ADR-0009). The login methods + browser sessions
-- form their own aggregate, owned by `IdentitiesService` (never folded into the
-- tenant aggregate). Both tables FK-cascade from `tenants`, so the existing tombstone
-- sweep (`delete_tombstoned_empty`) reaps them along with the tenant — no extra sweep
-- step is needed.

-- One row per login method. A `password` row carries an argon2id hash; a federated
-- row (`google`/`github`/…) carries none. All rows for a tenant resolve to it via the
-- verified email (the join key). `tenants` stays identity-only.
CREATE TABLE tenant_identities (
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Login method: 'password' | 'google' | 'github' | …
    provider     VARCHAR(32) NOT NULL,
    -- The provider's stable subject: the email for 'password', the provider's opaque
    -- subject/user id for an OIDC/OAuth provider.
    subject      VARCHAR(320) NOT NULL,
    -- argon2id PHC string for 'password'; NULL for a federated identity (the provider
    -- holds the secret). Never logged or echoed (invariant #1, extended to passwords).
    secret_hash  TEXT,
    -- The provider-verified email this identity resolved against (lowercased).
    email        VARCHAR(320) NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    -- A provider's subject is unique within that provider; this is the natural key the
    -- callback looks up to decide returning-vs-new.
    PRIMARY KEY (provider, subject)
);
CREATE INDEX idx_tenant_identities_tenant ON tenant_identities (tenant_id);

-- The browser-durable, revocable web credential (30-day sliding). The raw token lives
-- only in the httpOnly cookie; we store the SHA-256 hash so a DB read never yields a
-- usable credential (invariant #1). Logout / password-reset delete rows here.
CREATE TABLE sessions (
    -- hex(SHA-256(session token)). The raw token is never persisted.
    token_hash   VARCHAR(64) PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_sessions_tenant ON sessions (tenant_id);
