-- Wardnet DDNS — regional operational DNS state. Single fresh initialization
-- migration; the regional DB starts empty, so there is no prior schema to migrate.
--
-- One row per network, keyed by the Tenants-owned `network_id` (TEXT, matching the
-- global identity ids). It records what this region has *actually* published to
-- Cloudflare for that network: the reported IP, the FQDN the provisioner published
-- the A record under, the A-record id (for in-place report-IP updates), and the
-- live ACME DNS-01 TXT-record ids.
--
-- This table is the regional reconciler's local cache; Tenants remains the single
-- source of truth for desired state (see docs/adr/0001).

CREATE TABLE operational (
    -- The Tenants-owned network id this operational state belongs to.
    network_id         TEXT PRIMARY KEY,
    -- Last IP the daemon reported (IPv4 today; VARCHAR(45) leaves room for IPv6).
    ip                 VARCHAR(45),
    -- The FQDN the provisioner published the A record under (`<slug>.<parent>`).
    -- Stored so report-IP can update in place and the ACME handler can derive
    -- `_acme-challenge.<slug>...` without re-reading the mesh.
    fqdn               VARCHAR(255),
    -- Cloudflare A-record id, set by the provisioner's CAS claim. report-IP only
    -- ever updates the record this id points at — it never creates one.
    cf_a_record_id     VARCHAR(64),
    -- Cloudflare ACME DNS-01 TXT-record ids currently live for this network.
    cf_acme_record_ids TEXT[] NOT NULL DEFAULT '{}',
    updated_at         TIMESTAMPTZ NOT NULL
);
