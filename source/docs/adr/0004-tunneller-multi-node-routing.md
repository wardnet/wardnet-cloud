# 4. Tunneller is multi-node: mesh slug-resolution + a routing table + pull-reconcile abort

Date: 2026-06-17
Status: Accepted

## Context

The **Tunneller** is the regional edge that accepts a daemon's reverse-tunnel
WebSocket (`GET /v1/tunnel`) and forwards inbound L4 TLS connections arriving at its
SNI demuxer down that tunnel (the daemon terminates its own TLS — the private key
never leaves the device). A region runs **several active/active nodes** behind a load
balancer, so any node may accept the tunnel for a given network, and any node may
receive an inbound connection for it — and they are usually **not the same node**.

Three questions had to be answered together:

1. **How does a node turn a daemon's token into a routing key?** The daemon's
   network-scoped JWT identifies its network by opaque UUID (the `net` claim), but the
   SNI data plane routes by **vanity slug** (`<slug>.<parent>`). The node needs the
   slug at tunnel establishment.
2. **How does an inbound connection reach the node that holds the tunnel** when it
   lands on a different node?
3. **A tunnel can stay open for months.** If the network is decommissioned or the
   subscription lapses *after* establishment, an establishment-time check is not
   enough — the live data plane must be torn down.

## Decision

### Slug resolution via the mesh, not the JWT

The Tunneller stays **stateless of identity**: at tunnel establishment it resolves
`net → slug` with **one mesh read against Tenants** (`GET /v1/networks/{id}`), and
checks the owning tenant's subscription (`GET /v1/tenants/{id}`). No cache — the
channel lives for days, so one lookup is negligible, and a stale cache would be worse
than a lookup. This keeps the slug **out of the token** (the daemon never learns or
asserts its own routing key) and means **no `common::token` / `common::auth` change**
(`DaemonCaller` already carries `tenant_id` + `network`).

The two reads are **clean REST resource reads** on Tenants' mesh-mTLS plane that
return the *full* resource; **the policy lives in the caller** (the Tunneller's
`GET /v1/tunnel` handler), never in the Tenants endpoint. Their response DTOs
(`NetworkView` / `TenantView`) live in `common::contract`, shared by producer and
consumer.

### `tunnel_routes` table + private inter-node forward

Each node owns an **in-memory, per-node** registry keyed on slug (not persisted; a
restart just means daemons reconnect). A regional Postgres table `tunnel_routes`
`{slug PK, node_addr, network_id, tenant_id, last_seen}` records **which node holds
each tunnel**: the node `upsert`s on connect and deletes on disconnect; it refreshes
`last_seen` each reconcile pass; a TTL reaper purges rows orphaned by a crashed node.

The table is a **hint**, not the source of truth — each node's live registry is
authoritative. An inbound connection is handed to a `TunnelRouter`: `LocalRouter`
short-circuits a slug its own registry holds, else looks up `tunnel_routes`, dials the
owner's `node_addr` over a **private mTLS (mesh-CA) link**, sends a tiny preamble
`{slug, dest_port}`, and splices the raw L4 stream across. Forwarding **fails closed**:
a slug with no route, or one whose owning node's registry no longer holds it, is
dropped rather than mis-routed.

### Pull-reconcile abort (Tenants stays ignorant of the Tunneller)

A **per-node reaper** (consistent with ADR-0001: pull desired state; Tenants does not
call the Tunneller) iterates the node's *own* `tunnel_routes` rows and, for each, makes
the same two resource reads. Policy lives in the Tunneller: **abort** the live tunnel
(close WS → delete route → unregister) when the network is `404`/`deprovisioning` **or**
the tenant subscription is inactive. The same pass refreshes `last_seen`, so it doubles
as the node's heartbeat. A transient read failure leaves the tunnel up (fail safe — we
tear down only on a *positive* decommission signal).

## Consequences

- **No slug-in-JWT, no token-format change.** The trade-off is one mesh round-trip per
  tunnel establishment (acceptable for a long-lived channel) instead of a self-asserted
  routing key (which the daemon could spoof, and which couples token issuance to slug
  allocation).
- **Cross-node correctness is eventual.** A connection can briefly fail to route in the
  window between a tunnel moving nodes and the table catching up; it fails closed, and
  the client retries. We accept this over a globally-consistent routing store.
- **Decommission latency is one reconcile interval.** A lapsed subscription's tunnel
  survives at most one interval after the signal — bounded, and tunable per region.
- **Poll → push is a future option.** If Tenants load from per-node reconcile polling
  becomes a concern, Tenants could push decommission events; the pull model is the
  conservative default that keeps Tenants unaware of the Tunneller.
