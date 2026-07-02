# 12. Honor the remaining free trial when subscribing to the trial-equivalent plan

Status: Accepted

## Context

A tenant starts on a card-less managed **trial** (`trialing` subscription row, entitlement
`1/1`, `trial_expires_at = now + TRIAL_DAYS`; see ADR-0006, CONTEXT.md). Before this ADR,
subscribing to *any* plan converted the trial to paid and charged the first invoice
**immediately** — so a user with weeks of free trial left forfeited all of it the moment
they added a card. That is unfair and pushes users to delay subscribing (hurting
conversion and locking in the founder promotion later rather than sooner).

Stripe already models the needed behavior: a subscription created with
`subscription_data[trial_end]` stays `trialing` until that date, entitling the customer
with no charge, then bills at `trial_end`. And the projection/webhook layer already maps
a Stripe-`trialing` subscription to a **local `Active`** row (ADR-0011 / invariant #22),
distinct from the managed card-less trial (local `Trialing`, no Stripe ids) — so an
honored trial is granted service and is *not* touched by the managed-trial reaper.

The tension: honoring the trial is clearly right when the user picks the **trial-equivalent
plan** (Home, `1/1` — same entitlement they already have free). But if they pick a **higher**
tier, they are asking for more capacity *now*, and deferring the charge would hand them the
paid tier free for the rest of the trial.

## Decision

Whether a subscribe (or plan-change) **preserves or ends** the trial is decided by comparing
the chosen plan's entitlement to the trial's, not by plan name or level:

- **Trial-preserving** — chosen entitlement ≤ the trial's (`max_networks` **and**
  `max_daemons` both ≤ `1/1`, i.e. Home). Checkout sets `subscription_data[trial_end]` to
  the tenant's original `trial_expires_at`: the first charge defers to when the trial would
  have ended, entitlement stays `1/1`, and the plan + auto-applied promotion are locked in.
  No user warning — it is seamless.
- **Trial-ending** — chosen entitlement exceeds the trial's (Home HA / Pro). Immediate
  billing (the prior behavior). The account plane **warns and requires confirmation**,
  naming the trial days being forfeited, so the user can knowingly proceed or drop to Home.

Two consistency rules complete it:

1. **No future trial date ⇒ immediate, silently.** If `trial_expires_at` is already past
   (the tenant is in grace) or too close to now to be a valid Stripe `trial_end`, the
   trial-preserving path falls back to an immediate charge with no ceremony — there are no
   free days left to defer.
2. **Upgrades during an honored trial also end it.** A trial-preserving subscription always
   sits on Home (`1/1`), so any in-app upgrade necessarily exceeds the trial entitlement.
   Such an upgrade ends the Stripe trial (`trial_end = now`, charge immediately) behind the
   same confirmation — closing the subscribe-Home-then-upgrade loophole.

The backend is authoritative for the preserve-vs-end choice (`start_checkout` /
`change_plan` in `BillingService`, which reads the trial via the `SubscriptionReader` port
and the target entitlement from the catalog projection). The frontend independently derives
the same condition only to render the confirmation prompt.

## Considered alternatives

- **Always convert immediately (status quo)** — rejected: forfeits earned free time; the
  original complaint.
- **Honor the trial for every tier, granting the paid entitlement free until `trial_end`** —
  rejected: hands a higher tier's capacity away free for the rest of the trial with no
  signal, and makes "subscribe to Pro" mean "free Pro for weeks."
- **Key the decision on plan `level` (or hardcode "Home")** — rejected: the trial has no
  catalog `level` (it is `Entitlement::DEFAULT`), so this would hardcode a magic number and
  break if the catalog's numbering or the trial default ever changed. Entitlement comparison
  is robust to both.
- **Keep the trial entitlement (`1/1`) during a preserved subscription and grant the paid
  entitlement only at `trial_end`** — rejected for Home it is a no-op (same `1/1`), and for
  higher tiers we chose immediate billing instead, so there is no case where holding back a
  paid entitlement is needed.
- **Accept the subscribe-then-upgrade loophole as a bounded edge** — rejected in favour of
  consistency: the entitlement rule applies uniformly to subscribes and plan-changes.

## Consequences

- `create_checkout_session` gains an optional `trial_end`; `start_checkout` computes it from
  the current trial and the target entitlement.
- `change_plan`'s upgrade path must detect a still-trialing Stripe subscription and end the
  trial when the target exceeds the trial entitlement.
- The account plane gains a trial-forfeit confirmation before trial-ending changes.
- A `forever` promotion attached during the honored trial must still discount the first
  charge at `trial_end` even if that falls after the coupon's `redeem_by` (Stripe applies an
  already-attached coupon regardless; verified during real-Stripe e2e).
- Grace-period management + trial/renewal emails remain deferred to wardnet-cloud#29.
