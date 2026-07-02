// Sample data from the issue #19 spec: Pedro, Pro $8/mo, networks 2/3,
// devices 24/25, Visa •••• 4242, renews Jul 1. Confirm code 424242.

import type {
  BillingSubscriptionView,
  ConnectedIdentityView,
  DaemonView,
  Entitlement,
  InvoiceView,
  MeView,
  NetworkView,
  PaymentMethodView,
  PlanView,
  SubscriptionStatus,
  SubscriptionView,
} from "../api/contract";
import type { SubScenario } from "./scenario";

export const DEMO_CODE = "424242";
export const TENANT_ID = "tenant_pedro";
export const PRICE_BASIC = "price_basic_monthly";
export const PRICE_PRO = "price_pro_monthly";
export const PRICE_TEAM = "price_team_monthly";

const addDays = (base: Date, days: number): string =>
  new Date(base.getTime() + days * 86_400_000).toISOString();

const PAID_ENTITLEMENT: Entitlement = { max_networks: 3, max_daemons: 25 };
const FREE_ENTITLEMENT: Entitlement = { max_networks: 1, max_daemons: 5 };

const STATUS_BY_SCENARIO: Record<SubScenario, SubscriptionStatus> = {
  trial: "trialing",
  active: "active",
  grace: "past_due",
  cancelled: "canceled",
};

/** First day of next month (the "renews on Jul 1" anchor). */
function firstOfNextMonth(now: Date): string {
  return new Date(now.getFullYear(), now.getMonth() + 1, 1).toISOString();
}

export function buildSubscription(
  scenario: SubScenario,
  now = new Date(),
): SubscriptionView {
  const base = {
    id: "sub_pedro",
    status: STATUS_BY_SCENARIO[scenario],
    created_at: addDays(now, -40),
    updated_at: addDays(now, -1),
  };
  switch (scenario) {
    case "trial":
      return {
        ...base,
        entitlement: PAID_ENTITLEMENT,
        trial_expires_at: addDays(now, 5),
        current_period_end: null,
      };
    case "active":
      return {
        ...base,
        entitlement: PAID_ENTITLEMENT,
        trial_expires_at: null,
        current_period_end: firstOfNextMonth(now),
      };
    case "grace":
      // Expired 3 days ago; a 7-day grace window leaves ~4 days to renew.
      return {
        ...base,
        entitlement: PAID_ENTITLEMENT,
        trial_expires_at: null,
        current_period_end: addDays(now, -3),
      };
    case "cancelled":
      return {
        ...base,
        entitlement: FREE_ENTITLEMENT,
        trial_expires_at: null,
        current_period_end: addDays(now, -5),
      };
  }
}

export function buildMe(scenario: SubScenario, now = new Date()): MeView {
  return {
    tenant_id: TENANT_ID,
    email: "pedro@example.com",
    subscription: buildSubscription(scenario, now),
  };
}

/** The plan catalog (ascending by level). Pro is the current plan; it carries a live
 *  promo so the strike-through / promo path is exercised. */
export function buildPlans(now = new Date()): PlanView[] {
  return [
    {
      price_id: PRICE_BASIC,
      name: "Basic",
      level: 1,
      entitlement: { max_networks: 1, max_daemons: 5 },
      amount_cents: 500,
      currency: "usd",
      interval: "month",
      promo: null,
    },
    {
      price_id: PRICE_PRO,
      name: "Pro",
      level: 2,
      entitlement: PAID_ENTITLEMENT,
      amount_cents: 800,
      currency: "usd",
      interval: "month",
      promo: {
        amount_cents_after: 600,
        label: "Holiday",
        ends_at: addDays(now, 10),
      },
    },
    {
      price_id: PRICE_TEAM,
      name: "Team",
      level: 3,
      entitlement: { max_networks: 10, max_daemons: 100 },
      amount_cents: 2000,
      currency: "usd",
      interval: "month",
      promo: null,
    },
  ];
}

/** The Billing view: which plan the tenant is on, plus any pending downgrade. A paid
 *  scenario is on Pro; trial/cancelled have no Stripe subscription. */
export function buildBillingSubscription(
  scenario: SubScenario,
): BillingSubscriptionView {
  const isPaid = scenario === "active" || scenario === "grace";
  return {
    current_price_id: isPaid ? PRICE_PRO : null,
    pending_change: null,
    trialing: false,
  };
}

const NET_HOME = "net_home_lab";
const NET_PARENTS = "net_parents_house";

export function buildNetworks(now = new Date()): NetworkView[] {
  const common = { tenant_id: TENANT_ID, created_at: addDays(now, -30) };
  return [
    {
      ...common,
      id: NET_HOME,
      slug: "home-lab",
      display_name: "home-lab",
      region: "eu-west",
      provisioning_state: "active",
      updated_at: addDays(now, -2),
    },
    {
      ...common,
      id: NET_PARENTS,
      slug: "parents-house",
      display_name: "parents-house",
      region: "eu-central",
      provisioning_state: "active",
      updated_at: addDays(now, -2),
    },
  ];
}

/** 24 daemons total (14 home-lab + 10 parents-house) → devices 24/25. */
export function buildDaemons(now = new Date()): DaemonView[] {
  const make = (networkId: string, n: number): DaemonView[] =>
    Array.from({ length: n }, (_, i) => ({
      id: `${networkId}_daemon_${i}`,
      network_id: networkId,
      public_key: `pk_${networkId}_${i}`,
      created_at: addDays(now, -20 + i),
    }));
  return [...make(NET_HOME, 14), ...make(NET_PARENTS, 10)];
}

export function buildPaymentMethod(
  scenario: SubScenario,
): PaymentMethodView | null {
  // No card during trial; on file once paying (active/grace); cleared after cancel.
  if (scenario === "active" || scenario === "grace") {
    return { brand: "visa", last4: "4242", exp_month: 8, exp_year: 2027 };
  }
  return null;
}

export function buildInvoices(
  scenario: SubScenario,
  now = new Date(),
): InvoiceView[] {
  if (scenario === "trial") return [];
  const ym = (d: Date) => d.toISOString().slice(0, 10);
  const monthsAgo = (m: number) =>
    ym(new Date(now.getFullYear(), now.getMonth() - m, 1));
  return [
    {
      date: monthsAgo(0),
      amount_cents: 800,
      currency: "usd",
      status: "paid",
      hosted_url: "https://billing.example.com/invoice/3",
    },
    {
      date: monthsAgo(1),
      amount_cents: 800,
      currency: "usd",
      status: "paid",
      hosted_url: "https://billing.example.com/invoice/2",
    },
    {
      date: monthsAgo(2),
      amount_cents: 800,
      currency: "usd",
      status: "paid",
      hosted_url: "https://billing.example.com/invoice/1",
    },
  ];
}

export function buildIdentities(now = new Date()): ConnectedIdentityView[] {
  return [
    { provider: "google", label: "pedro@gmail.com", connected_at: addDays(now, -38) },
    { provider: "password", label: "pedro@example.com", connected_at: addDays(now, -40) },
  ];
}
