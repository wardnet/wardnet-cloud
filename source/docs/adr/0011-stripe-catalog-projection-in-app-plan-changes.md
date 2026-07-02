# 11. Stripe is the plan catalog; a projected read-model serves it; plan changes and card updates are in-app (no Customer Portal)

Date: 2026-06-30
Status: Accepted

Refines the billing model of [0010](0010-license-billing-split-ports.md) (the
license/payment split). Does not change which aggregate grants entitlement — that
remains the `subscriptions` license, fed live from the webhook (invariant #22).

## Context

Before this, the "plan" was known in three places that drifted: the SPA hardcoded the
plan name / price string / Stripe `price_id` (`plan.ts`, with a placeholder
`price_pro_monthly` that broke Checkout), the backend derived entitlement from Stripe
price metadata only at webhook time, and Stripe held the real cost. There was no way to
list purchasable plans, change plan in-app, or run a promotion; the Customer Portal was
the only path for plan switches and card updates, and it had never been configured
(creating a portal session errors without a saved configuration).

The "My Account" work needs: a real plan catalog the SPA reads (not hardcoded), in-app
upgrade/downgrade, seasonal promotions, and a coherent all-in-app billing UX. All of
this is *product/pricing* data, and we had already decided Stripe is the catalog owner.

## Decision

**Stripe is the single source of truth for the plan catalog** — plans, costs,
entitlements, levels, and promotions all live in Stripe. A **plan** is a recurring
Stripe Price whose metadata carries `max_networks` / `max_daemons` (the entitlement, as
before) **and** a unique integer `level` that totally orders the catalog. A price
missing any of those keys, or with a duplicate `level`, is excluded from the catalog
(safe-closed, the same posture as missing entitlement metadata).

**A projected read-model serves the catalog, not live Stripe calls.** A background
worker in the Billing aggregate syncs Stripe → a Billing-owned projection table
(plans + promotions), and `GET /v1/plans` (public, bootstrap group) plus all
server-side promo derivation read *that table*, never Stripe on the hot path. The worker
is the **only** writer to the projection, so Stripe stays the sole authority. The
projection stores each promotion's actual window (`wardnet_promo_start` → Stripe
`redeem_by`) and discount, so **promo live-ness is evaluated against the current clock at
request time** — expiry is precise to the second regardless of sync age; only a newly
created/edited plan or promo lags by at most the sync interval. The sync is
**webhook-triggered** (Stripe catalog events — `price.*` / `product.*` / `coupon.*` /
`promotion_code.*` — added to the existing webhook wake the worker, live in seconds) with
a **periodic worker (~5h) as the dropped-event backstop** (the same events + reconcile
pattern as invariant #23). A catalog older than a hard staleness bound (~5 days) is
treated as invalid: `GET /v1/plans` returns 503 rather than serve ancient pricing.

**Plan changes are in-app, on an already-paid subscription**
(`POST /v1/tenants/{id}/billing/change-plan`, USER, owner-checked). Up vs down is decided
by comparing the target `level` to the current one. An **upgrade** applies immediately as
a Stripe subscription update with `proration_behavior=create_prorations` (the prorated
difference lands on the next invoice — no mid-cycle charge that could fail). A
**downgrade** is scheduled via a **Stripe Subscription Schedule** to take effect at
`current_period_end`, so the tenant keeps the entitlement it paid for until the boundary;
the existing `customer.subscription.updated` webhook flips entitlement down at the
boundary. `change-plan` always reconciles against any existing schedule first
(release-then-act), so re-entry is idempotent (re-selecting the current plan cancels a
pending downgrade). A `trialing`/`canceled` tenant has no Stripe subscription to change
and is rejected — it subscribes via Checkout. The endpoint returns `202 { effect,
effective_at }`; the real state lands asynchronously via the webhook. The pending
scheduled downgrade is surfaced by a **Billing** read (read from the Stripe schedule, not
a field on the provider-agnostic `SubscriptionView`).

**Promotions are global, seasonal, auto-applied, and server-side only.** A promotion is a
Stripe coupon flagged `wardnet_auto_apply=true` whose window contains now and whose native
`applies_to.products` covers the plan; the best discount wins on overlap. The SPA never
passes a coupon — the backend re-derives the live coupon and applies it
(`discounts:[{coupon}]`) at Checkout and at upgrade. `PlanView.promo` is display-only.
Promotions affect *cost* only, never entitlement, and never touch the Subscriptions
aggregate. If a promo lapses between display and application, Stripe rejects the coupon;
we **do not silently charge full price** — `change-plan`/checkout return `409
PromoUnavailable { actual_amount_cents, currency }` and the SPA re-confirms at the real
price before proceeding.

**The Stripe Customer Portal is removed entirely.** All billing actions are in-app, with
card entry always on a Stripe-served surface: subscribe and **card update** use hosted
Checkout (the latter in `setup` mode), `past_due` recovery links the open invoice's
Stripe-hosted pay page (`hosted_invoice_url`, already surfaced by `InvoiceView`), plan
changes use `change-plan`, cancel stays `PATCH /v1/tenants/{id}`, and invoice history is
the existing proxied read. SAQ-A is preserved (no card data in our app); there is no
manual "set default payment method + pay invoice" orchestration to lose payments in.

## Considered alternatives

- **Backend config (or hybrid config+Stripe) as catalog SoT** — rejected: cost would
  live in two places, re-introducing the drift this removes.
- **Live Stripe calls per `/v1/plans` with a short in-memory TTL cache** — workable and
  less code, but keeps Stripe on the hot read path, hits rate limits, and gives each
  replica its own view. The projection takes Stripe off the read path entirely and gives
  one consistent catalog; its outage tolerance is a bonus (no transaction is possible
  while Stripe is down anyway).
- **Keep the Customer Portal for card update / downgrades** — rejected: the product wants
  a fully in-app UX, and hosted `setup`-mode Checkout + the hosted invoice page cover the
  Portal's only remaining jobs without its redirect.
- **`change-plan` returns the updated `SubscriptionView` synchronously** — rejected: the
  license change lands via the webhook; returning a "fresh" view synchronously would lie
  for the upgrade and be meaningless for the scheduled downgrade.

## Consequences

- Grace windows are *not* migrated to Stripe metadata here — that is deferred to
  wardnet-cloud#29 (which also covers trial/grace notification emails); the trial grace in
  particular cannot be per-price because a card-less trial has no Stripe price.
- Adding/repricing a plan or running a promotion is a Stripe-only change (no deploy),
  live within seconds via the catalog webhook.
- Annual (multi-interval) plans are out of scope here, but `PlanView.interval` is a real
  field read from the price (not hardcoded), so annual is a later additive change.
- A new Billing projection table + sync worker join the existing reconcile/sweep loops as
  N-replica-safe idempotent background work.
