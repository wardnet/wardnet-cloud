// The subscription state is the spine: every status pill, CTA, banner, and
// blocked/near-limit action derives from here. See issue #19 "reconciliation".

import type {
  Entitlement,
  MeView,
  SubscriptionStatus,
  SubscriptionView,
} from "../api/contract";
import type { MeterTone } from "@wardnet/ui";

export type Lifecycle = "trial" | "active" | "grace" | "cancelled";

export interface AccountState {
  lifecycle: Lifecycle;
  /** Display label for the status pill. */
  statusLabel: string;
  /** DS Pill variant for the status pill. */
  pillVariant: "ok" | "warn" | "info" | "ghost";
  /** CSS colour for the Overview status-card accent stripe. */
  stripeColor: string;
  /** Premium features (dynamic DNS, tunneling) are on (trial or active). */
  isActive: boolean;
  /** Premium is paused (grace or cancelled) — block premium actions. */
  isPremiumPaused: boolean;
  entitlement: Entitlement;
  /** End of the current paid period (renewal/cancellation anchor). */
  periodEnd: Date | null;
  /** Trial expiry (trial lifecycle only). */
  trialEnd: Date | null;
  /** The raw subscription, when present. */
  subscription: SubscriptionView | null;
}

const FREE_ENTITLEMENT: Entitlement = { max_networks: 1, max_daemons: 1 };

const LIFECYCLE_BY_STATUS: Record<SubscriptionStatus, Lifecycle> = {
  trialing: "trial",
  active: "active",
  past_due: "grace",
  canceled: "cancelled",
};

interface Presentation {
  statusLabel: string;
  pillVariant: AccountState["pillVariant"];
  stripeColor: string;
  isActive: boolean;
}

const PRESENTATION: Record<Lifecycle, Presentation> = {
  trial: {
    statusLabel: "Trial",
    pillVariant: "info",
    stripeColor: "var(--accent)",
    isActive: true,
  },
  active: {
    statusLabel: "Active",
    pillVariant: "ok",
    stripeColor: "var(--accent)",
    isActive: true,
  },
  grace: {
    statusLabel: "Grace",
    pillVariant: "warn",
    stripeColor: "var(--warn)",
    isActive: false,
  },
  cancelled: {
    statusLabel: "Cancelled",
    pillVariant: "ghost",
    stripeColor: "var(--ink-4)",
    isActive: false,
  },
};

const parseDate = (iso: string | null): Date | null =>
  iso ? new Date(iso) : null;

/**
 * Derive the account presentation state from `GET /v1/me`. A `null` subscription
 * (the backend returns no row for a fully-cancelled tenant) is treated as the
 * cancelled lifecycle with free-tier entitlements.
 */
export function deriveAccountState(me: MeView): AccountState {
  const sub = me.subscription;
  const lifecycle: Lifecycle = sub
    ? LIFECYCLE_BY_STATUS[sub.status]
    : "cancelled";
  const p = PRESENTATION[lifecycle];

  return {
    lifecycle,
    statusLabel: p.statusLabel,
    pillVariant: p.pillVariant,
    stripeColor: p.stripeColor,
    isActive: p.isActive,
    isPremiumPaused: !p.isActive,
    entitlement: sub?.entitlement ?? FREE_ENTITLEMENT,
    periodEnd: parseDate(sub?.current_period_end ?? null),
    trialEnd: parseDate(sub?.trial_expires_at ?? null),
    subscription: sub,
  };
}

export interface Usage {
  used: number;
  max: number;
  remaining: number;
  /** ≤ 1 slot left (or over). */
  nearLimit: boolean;
  tone: MeterTone;
  pct: number;
}

/**
 * Usage-vs-limit tone rules. At/over the limit is danger; within one slot of a
 * nearly-full pool is warn (ratio gate so small pools like networks 2/3 stay
 * calm while a tight pool like devices 24/25 warns); otherwise accent.
 */
export function computeUsage(used: number, max: number): Usage {
  const remaining = max - used;
  const ratio = max <= 0 ? 1 : used / max;
  const tone: MeterTone =
    remaining <= 0 ? "danger" : remaining <= 1 && ratio >= 0.85 ? "warn" : "accent";
  return {
    used,
    max,
    remaining,
    nearLimit: tone !== "accent",
    tone,
    pct: max <= 0 ? 0 : Math.min(100, Math.round((used / max) * 100)),
  };
}
