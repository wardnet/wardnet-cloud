-- Regional DDNS operational state — PostgreSQL (per-region DB).
--
-- After the identity collapse (#610 3a-ii) the regional DB holds ONLY operational
-- DNS state. Identity, names, registration challenges, and the registration log
-- all live in the global Tenants DB now.
--
-- operational — one row per install that has published DNS state. Created lazily
--   on the first PUT /ip (ON CONFLICT upsert), so a registered-but-not-yet-active
--   install simply has no row. `cf_acme_record_ids` holds the live ACME DNS-01
--   TXT record IDs — a per-user wildcard cert publishes two values at the one
--   `_acme-challenge.<name>` name, so it is a list. `NOT NULL DEFAULT '{}'` makes
--   "no live challenge" the empty array.
CREATE TABLE operational (
    install_id          VARCHAR(36)  PRIMARY KEY,
    ip                  VARCHAR(45),
    cf_a_record_id      VARCHAR(64),
    cf_acme_record_ids  TEXT[]       NOT NULL DEFAULT '{}',
    updated_at          TIMESTAMPTZ  NOT NULL
);
