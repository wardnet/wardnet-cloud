# 3. DDNS uses a hybrid write model (provisioner creates, report-IP only updates)

Date: 2026-06-16
Status: Accepted

## Context

The regional DDNS service reconciles Cloudflare toward the desired state Tenants
owns (ADR-0001): a short-interval **provisioner** drives `provisioning → active`
and a long-interval **reaper** drives `deprovisioning →` row-deletion. Daemons
separately push their current IP to a public **report-IP** endpoint.

Two questions had to be answered together:

1. **Who creates the Cloudflare A record** — the daemon's report-IP call, or the
   provisioner? If report-IP can create, a report that arrives *after* the reaper
   has torn a record down would **resurrect** it, leaking a record for a
   deprovisioned network. If only the provisioner creates, report-IP needs an
   already-published record to update.
2. **How do N regional replicas avoid duplicates?** Running more than one DDNS pod
   per region (for availability) means two provisioners can race to publish the
   same network, and a pod that crashes mid-create can orphan a record.

## Decision

**Hybrid write model.**

- The **provisioner is the sole *creator*** of the A record. Only it sees the
  slug→FQDN mapping (from the mesh `NetworkView`) and it pulls **live** desired
  state each tick, so it never creates a record for a network that is already
  deprovisioning. `provisioning → active` fires once the record is published —
  i.e. once an IP has been reported; a `provisioning` network with no IP yet is
  **skipped** until a later tick.
- **report-IP only ever *updates in place***, and only when a `cf_a_record_id` is
  already stored. It never creates. A report racing a teardown therefore cannot
  resurrect the record — it merely re-stores the IP into a (possibly fresh) row,
  which is harmless and bounded by the daemon JWT's short TTL. (The repository's
  `record_ip` writes the IP column only — never `fqdn`/`cf_a_record_id` — so a
  report cannot clobber a concurrently-set claim.)

**Adopt-or-create + CAS claim** for N-replica safety. The provisioner's publish is:

1. **adopt-or-create** — look up an existing A record for the FQDN and update it in
   place if found, else create a fresh one;
2. **CAS-store** the record id into the operational row, guarded by
   `WHERE cf_a_record_id IS NULL`;
3. if the CAS **loses** to a peer, best-effort **delete** the record we hold —
   unless it is the very record the winner stored (we adopted the winner's live
   record), so we drop only a true duplicate.

ACME DNS-01 is orthogonal (the Pi terminates its own TLS under SNI passthrough);
its TXT replace-set persists with a compare-and-set so a concurrent challenge
write is detected (`409 Conflict`) rather than silently clobbered.

## Consequences

- Records cannot leak or be resurrected: creation is gated on live desired state,
  and the only unsynchronised writer (report-IP) cannot create.
- Multiple DDNS replicas per region are safe with no leader election and no extra
  coordination: the create path closes both the concurrent-replica duplicate and
  the crash-mid-create orphan, and reaper/transition are already idempotent
  (Cloudflare delete treats `404` as success; the Tenants PATCH is a guarded SQL
  CAS).
- report-IP is cheap and never blocks on the mesh; a network simply isn't
  reachable by name until its first IP report lets the provisioner publish.
- The cost is a stored `fqdn` per network (so report-IP can update in place and
  ACME can derive `_acme-challenge.<fqdn>`) and one extra Cloudflare lookup on the
  provisioner's adopt path.
