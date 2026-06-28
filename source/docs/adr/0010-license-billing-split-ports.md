# 10. License (Subscription) vs Billing split; two-port inter-crate boundary

Date: 2026-06-28
Status: Accepted

Supersedes [0006](0006-subscriptions-aggregate.md). Refines the eventing rules of
[0007](0007-domain-events-reactors.md).

## Context

[ADR-0006](0006-subscriptions-aggregate.md) made entitlement a `subscriptions`
aggregate with a card-less managed trial, and folded Stripe into it: the
`SubscriptionService` owned both the **license** (status / entitlement / trial+grace)
*and* the **payment provider** (Checkout/Portal, the webhook, the idempotency ledger,
the `stripe_*` reference ids on the `subscriptions` row). Two genuinely different
domains were intermingled in one crate:

- **Subscription = the license.** *What* entitlement a tenant currently holds and its
  lifecycle (`trialing → active → past_due → canceled`, grace windows). Provider-agnostic;
  the source of truth for entitlement.
- **Billing = how it's paid for.** The payment provider (Stripe today), hosted
  Checkout/Portal, webhooks, the idempotency ledger, the provider-reference ids. Swappable.

The "My Account" initiative needs these as independent units that could later be lifted
into their own services without a domain rewrite. That requires a real seam *now* — one
the compiler enforces, not a convention.

[ADR-0007](0007-domain-events-reactors.md)'s `EventPublisher` also leaked its transport:
`subscribe()` returned a `tokio::sync::broadcast::Receiver`, so no other delivery
mechanism could ever be substituted without changing every reactor signature.

## Decision

**Three independent aggregate crates, composed into one binary.** `subscriptions` (the
license), `billing` (the payment provider), and `tenants` (identity/networks/daemons +
the Identities aggregate) are separate workspace crates. They depend on `wardnet_common`
and **never on each other** — the boundary is a Cargo fact, so a crate physically cannot
name a sibling's concrete type. A single composition-root binary crate (`app-tenants`,
artifact `wardnet-tenants`) is the only crate that depends on all three; it instantiates
each concrete service and injects the others as `dyn` **port** trait objects. (The same
uniform lib/bin layout is applied to `ddns` and `tunneller` — a domain lib + a thin bin —
so packaging is orthogonal to domain code across the workspace.)

**Two port mechanisms, not "everything is an event"** (all ports + the DTOs they carry
live in `wardnet_common`):

1. **`EventBus` / `EventStream`** — fire-and-react state-change notifications
   (`TenantCreated`, `TenantDeregistered`, `SubscriptionDeactivated`). The redesigned
   port leaks no transport: `publish(&DomainEvent)` and `subscribe(group) ->
   Box<dyn EventStream>` (with `EventStream::next() -> Option<Delivery>`; `Delivery::ack()`
   is auto-ack in-proc, a broker ack later). Only the in-process `tokio::broadcast`
   adapter ships now (parity with today); the `group` arg is a no-op in-proc and the
   competing-consumer key an AMQP/RabbitMQ adapter will use later. `DomainEvent` is
   serde-serializable with a **stable, versioned wire format** so the broker adapter is
   drop-in.

2. **Synchronous query/command client-ports** — answers needed *now*:
   - **`SubscriptionReader`** — entitlement reads (`current` / `is_active`) used by
     `register_network`, daemon JWT minting, and the resource-read view / Tunneller's
     `TenantView`. Returns the `SubscriptionView` DTO, never a concrete row.
   - **`SubscriptionCommands`** — the one-way **Billing → Subscription** write edge
     (`convert_trial_to_paid` / `update_paid` / `mark_past_due` / `cancel`). Billing's
     webhook drives license transitions **only** through this; Subscription never calls
     Billing (mirrors the Identities → Tenants edge). Only primitives + `common` types
     cross — no `stripe_*` id ever reaches Subscription.
   - **`BillingPort`** — the composition/Tenants → Billing edge (`start_checkout` /
     `billing_portal` / `handle_webhook`).

   In-process adapters are direct method calls; each gets a mesh-mTLS HTTP adapter later
   (out of scope here) with no change to the consuming domain code.

**Data move.** `stripe_customer_id` / `stripe_subscription_id` / `price_id` leave the
`subscriptions` row for a new Billing-owned **`billing_customers`** table keyed by
`(tenant_id, provider)`; the `processed_stripe_events` ledger becomes Billing-owned.
`subscriptions` retains only provider-agnostic license columns. Each crate owns its own
`migrations/` dir (compile-time-relative `sqlx::migrate!`), and the composition root
merges the per-crate `Migrator`s into one ordered history against the single shared DB's
default `_sqlx_migrations` table — a forward-only `billing_customers` create + back-fill
(earlier timestamp) precedes the `subscriptions` drop-columns migration. `SubscriptionView`
drops its `stripe_*` fields accordingly (provider refs surface via Billing's own read
endpoints later).

## Consequences

- **The boundary is compiler-enforced.** `billing` cannot reference a `subscriptions`
  or `tenants` type; the only shared surface is `wardnet_common` (ports + contract DTOs +
  the event bus). A CI guard greps the three manifests/sources so it cannot regress.
- **Reconcile is the correctness guarantee across *every* transport.** Events are a
  best-effort fast path; the periodic reconcile re-derives desired state. This holds for
  the in-process adapter and any future broker, so **all reactors must be idempotent and
  tolerate at-least-once delivery.** The broker buys durability/decoupling, never
  correctness. The cross-aggregate reconcile (tenant ↔ license) now lives at the
  composition root, since it spans two aggregates.
- **Atomicity relaxes at the seam.** Trial→paid was one DB transaction inside one
  aggregate; it is now a Billing write (`billing_customers`) followed by a
  `SubscriptionCommands` call. Billing records the provider ref *before* the command so a
  retry after a partial failure still maps the subscription to its tenant, and the webhook
  ledger only records an event after its effect lands — at-least-once + idempotent, per
  the invariant above.
- **Strictly behavior-preserving** for clients: same endpoints, same auth, same DB
  semantics. The deploy unit (`wardnet-tenants` binary, its mesh identity + `aud`) is
  unchanged; only the Cargo package that owns each binary moved.
- **A future out-of-process split is an adapter + config change**, not a rewrite: swap the
  in-proc port adapters for mesh-HTTP ones and the event bus for a broker, and split the
  shared DB — the domain code is already blind to which it is talking to.
