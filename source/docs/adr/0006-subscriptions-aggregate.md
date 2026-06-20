# 6. Entitlement is granted by a subscription aggregate, with a card-less managed trial

Date: 2026-06-18
Status: Accepted

## Context

The first cut put billing state **on the tenant row**: `entitlement` (a typed
`{max_networks, max_daemons}` JSONB), `subscription_status` (`active`/`canceled`), and a
reserved `subscription_id`. Every self-service signup was hard-wired to `active` with a free
`1/1` entitlement **forever** — there was no trial, no paid plan, and no billing source of
truth. WS-G wires real billing (Stripe) and a free-trial business model.

Two questions had to be answered:

1. **Where does entitlement live?** On the tenant, or on a billing object?
2. **How is the free trial modelled** when we deliberately collect **no card** at signup
   (a lean, frictionless funnel — the user chose this), yet still need to time-box it and
   eventually disable service?

## Decision

**1. Extract a `subscriptions` aggregate; entitlement is granted by the subscription, never the
tenant.** A plan grants the limits, so the limits belong to the subscription, not the account.
The `tenants` row is now identity-only (`id`, `email`, `created_at`, `deregistered_at`). All
billing data — `status`, `entitlement`, the Stripe ids, `trial_expires_at`,
`current_period_end` — lives on `subscriptions`.

**2. 1:N history, one live row.** A tenant accrues subscription rows over time; at most one is
**live** (non-`canceled`), enforced by a partial unique index
(`uq_subscriptions_live ON (tenant_id) WHERE status <> 'canceled'`). "The current subscription"
is therefore a point lookup. Trial→paid conversion **cancels the trial row and inserts a paid
row** in one transaction (cancel-before-insert satisfies the index).

**3. The free trial is itself a subscription.** A tenant is created with a `trialing` row
(entitlement `1/1`, no Stripe ids, `trial_expires_at = now + TRIAL_DAYS`). There is no separate
"trial" concept bolted onto the tenant — the trial and the eventual paid subscription are the
same lifecycle on the history. Status set: `{trialing, active, past_due, canceled}`.

**4. We manage the trial clock; two grace windows.** Service is entitled while the current
subscription is `active`, or `trialing` within `trial_expires_at + TRIAL_GRACE`, or `past_due`
within `current_period_end + PAYMENT_GRACE`. A periodic **reaper** cancels rows past their
grace (which cascades network deprovisioning — see ADR-0007). Defaults: 60-day trial, 15-day
trial grace, 15-day payment grace (all env-configurable). `from_db` on the status enum maps an
unknown value to `canceled` — **safe-closed**: an unrecognized billing state must never grant
service.

**5. Plan→entitlement comes from Stripe price metadata.** On a `customer.subscription.*`
webhook, the entitlement is read from the purchased price's `max_networks` / `max_daemons`
metadata. Adding or retiring a plan is a Stripe-dashboard change, **zero deploy**. If the
metadata is missing/unparseable the webhook **declines to grant** (logs and leaves the trial in
place) rather than guessing — safe-closed again.

**6. The wire `TenantView` embeds the current `SubscriptionView`.** Consumers (the Tunneller)
read the embedded subscription; a *missing* subscription means "not entitled". The view's
`is_active()` is grace-free (a current row is non-canceled by construction; the reaper enforces
the time bound producer-side), so a consumer needs no trial/grace config.

## Consequences

- One source of truth for entitlement; the tenant is a pure identity root.
- Adding a limit dimension or a plan needs no migration (JSONB) and no deploy (Stripe metadata).
- The reaper interval bounds how stale "entitled" can be, but with day-scale grace windows an
  hourly reaper is far inside tolerance. `mint_jwt` additionally enforces the grace at issue
  time, so token issuance is exact regardless of reaper lag.
- `stripe_customer_id` lives on the subscription (carried forward across the history on
  re-subscribe), keeping the whole billing surface inside the one aggregate.
