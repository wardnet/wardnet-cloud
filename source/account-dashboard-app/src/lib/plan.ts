// Plan presentation helpers. The catalog itself is fetched from `GET /v1/plans`
// (Stripe is the source of truth — ADR-0011); nothing about a plan is hardcoded here.
import type { PlanView } from "../api/contract";
import { formatMoney } from "./format";

/** Short interval label: "month" → "mo", "year" → "yr" (else the raw value). */
export function intervalLabel(interval: string): string {
  if (interval === "year") return "yr";
  if (interval === "month") return "mo";
  return interval;
}

/** The price the customer pays now (promo-aware), in minor units. */
export function effectiveAmountCents(plan: PlanView): number {
  return plan.promo ? plan.promo.amount_cents_after : plan.amount_cents;
}

/** "$8/mo" using the effective (promo) price. */
export function formatPlanPrice(plan: PlanView): string {
  return `${formatMoney(effectiveAmountCents(plan), plan.currency)}/${intervalLabel(
    plan.interval,
  )}`;
}

/** "$10" — the undiscounted list price (for a strike-through when a promo is live). */
export function formatListPrice(plan: PlanView): string {
  return formatMoney(plan.amount_cents, plan.currency);
}
