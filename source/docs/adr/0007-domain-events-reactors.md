# 7. Cross-aggregate side-effects flow through in-process domain events + reactors

Date: 2026-06-18
Status: Accepted

## Context

WS-G split billing into its own [`subscriptions` aggregate](0006-subscriptions-aggregate.md),
owned by a new `SubscriptionService` distinct from the existing `TenantsService` (which owns
tenants/networks/daemons). That split surfaced cross-aggregate side-effects:

- Creating a tenant must open its **trial subscription** (tenant → subscription).
- Cancelling/expiring a subscription must **deprovision the tenant's networks**
  (subscription → network).

The **hard architectural rule** for this codebase: *a service holds only its own aggregate's
repositories.* `TenantsService` must never hold the `SubscriptionRepository`, and
`SubscriptionService` must never hold the `NetworkRepository`. So neither side-effect can be a
direct foreign-repository write. The question was how the aggregates coordinate.

## Decision

**Services raise domain events; others react.** A small in-process event bus
(`wardnet_common::event`: an `EventPublisher` trait + a `BroadcastEventBus` over
`tokio::sync::broadcast`, mirroring the daemon's design) carries a `DomainEvent` enum
(`TenantCreated`, `TenantDeregistered`, `SubscriptionDeactivated`). Long-running **reactors**
subscribe and turn each event into a call on the **owning** service's method:

- `TenantsService` publishes `TenantCreated` → the **subscription reactor** calls
  `SubscriptionService::create_trial`.
- `TenantsService` publishes `TenantDeregistered` → the subscription reactor calls
  `SubscriptionService::cancel`.
- `SubscriptionService::{cancel, expire_overdue}` publish `SubscriptionDeactivated` → the
  **network reactor** calls `TenantsService::deprovision_networks_for` (which owns the network
  repo).

**Reads stay direct** (a CQRS split): `TenantsService` obtains the current subscription by
calling `SubscriptionService::current(...)` — a *service method*, never the foreign repository.
Only write-side side-effects flow as events. The dependency graph is one-way
(`TenantsService → SubscriptionService` for reads); reactors are spawned tasks, not service-held
edges, so there is no cycle.

**The bus is best-effort, so reactors are idempotent and a reconcile is the guarantee.**
`tokio::broadcast` can drop on lag, so every reactor is idempotent (a replayed `TenantCreated`
is a no-op; `create_trial` only inserts when the tenant has *no* subscription history, so it
never resurrects a reaped trial). A periodic `TenantsService::reconcile` closes any
dropped-event gap: for a live tenant with no subscription it backfills the trial (or, if history
exists, deprovisions its networks). **Events are the fast path; reconciliation is the
guarantee** — the same desired-state ethos as ADR-0001.

## Consequences

- The aggregates stay decoupled: no service reaches into another's repository, and write-side
  coordination is explicit and observable (events are loggable, and the reactors are the only
  place a foreign side-effect happens).
- **Tenant→trial is eventually consistent.** A client racing enroll→token before the
  subscription reactor lands sees a transient `mint_jwt` refusal; idempotent retry + the
  reconcile backfill close it. In practice the in-process reactor lands well within a request
  round-trip, and the bus capacity (1024) makes drops vanishingly rare.
- Tests drive the reactors deterministically with a synchronous "pump" (drain the published
  events through the same reactor handlers to a fixpoint) instead of racing spawned tasks.
- New cross-aggregate side-effects extend the `DomainEvent` enum + a reactor, never a new
  cross-service repository dependency.
