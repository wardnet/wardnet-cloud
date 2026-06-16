# 1. DNS is reconciled from desired state, not requested by the daemon

Date: 2026-06-16
Status: Accepted

## Context

A daemon needs a public DNS record (`<vanity>.<zone>`) pointing at its IP, and that
record must be torn down when the network is cancelled or removed. The earlier
design had the daemon call the DDNS service directly to create/delete records, and a
single "reaper" that asked DDNS "which of my install ids are dead?" (a push/introspect
model). That left two problems: the daemon had to know about and reach DDNS for
lifecycle (not just IP), and record cleanup leaked when a deregister only tombstoned
the identity.

## Decision

Tenants holds the **desired state** of every network as a `provisioning_state`
(`provisioning → active → deprovisioning`). The regional DDNS service runs two
**pull-loops** that reconcile Cloudflare toward that desired state:

- a short-interval **provisioner**: `GET …?provisioningState=provisioning` → publish
  the record → `PATCH → active`;
- a long-interval **reaper**: `GET …?provisioningState=deprovisioning` → delete the
  record → `PATCH → deprovisioned`, which deletes the network row (freeing the slug).

The daemon's only contact with DDNS is **pushing its current IP**. The work queue is
exposed over the mesh-mTLS plane (`GET/PATCH /v1/networks`), cursor-paginated so a
stuck item cannot wedge a drain. This replaces the `POST /v1/introspect` endpoint.

## Consequences

- Lifecycle is driven by one source of truth (Tenants); DNS is an eventually-
  consistent side effect. Cancel/remove cannot leak records — the reaper converges.
- DDNS becomes a stateless controller over a work queue; adding regions is just more
  pullers filtered by `region`.
- A transient Tenants/mesh outage delays cleanup but never blocks daemons or crashes
  DDNS; the next tick retries.
- The daemon is simpler and never needs DDNS reachability for anything but IP.
