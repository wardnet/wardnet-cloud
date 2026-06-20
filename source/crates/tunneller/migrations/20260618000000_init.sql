-- Regional Tunneller DB: the slug → node_addr ownership map.
--
-- Each node writes its ownership of a tunnel on connect (upsert) and deletes it on
-- disconnect (own-node-guarded). The owning node refreshes `last_seen` each
-- reconcile pass; a TTL reaper purges rows orphaned by a crashed node. The table is
-- a routing HINT — each node's in-memory registry is the source of truth.

CREATE TABLE tunnel_routes (
    slug        TEXT        PRIMARY KEY,
    node_addr   TEXT        NOT NULL,
    network_id  TEXT        NOT NULL,
    tenant_id   TEXT        NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL
);

-- list_owned(node_addr): the abort reaper's per-node work list.
CREATE INDEX tunnel_routes_node_addr_idx ON tunnel_routes (node_addr);
-- reap_expired(deadline): the TTL reaper's orphan scan.
CREATE INDEX tunnel_routes_last_seen_idx ON tunnel_routes (last_seen);
