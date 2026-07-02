import { Network } from "lucide-react";
import { useNavigate } from "react-router-dom";
import {
  Button,
  Card,
  CardAction,
  CardContent,
  CardHeader,
  CardSubtitle,
  CardTitle,
  Heading,
  Pill,
  StatTile,
  Text,
} from "@wardnet/ui";
import {
  useBillingSubscription,
  useDaemons,
  useNetworks,
  usePlans,
} from "../../api/queries";
import type { AccountState } from "../../account/spine";
import { computeUsage } from "../../account/spine";
import { EmptyState, QueryStates } from "../../components/feedback";
import { daysUntil, formatDate } from "../../lib/format";
import { networkStatus } from "../../lib/network";
import { formatPlanPrice } from "../../lib/plan";
import { useAccount } from "./AccountContext";
import layout from "./AccountLayout.module.css";
import s from "./Overview.module.css";

interface StatusContent {
  headline: string;
  sentence: string;
  ctaLabel: string;
  ctaVariant: "default" | "ghost";
  onCta: () => void;
  headlineColor: "ink" | "warn" | "ink-3";
}

function useStatusContent(account: AccountState): StatusContent {
  // Billing actions live on the Subscription tab (the catalog picker + Checkout); the
  // Overview CTA just routes there.
  const { tenantId } = useAccount();
  const navigate = useNavigate();
  const toBilling = () => navigate("/subscription");
  const plans = usePlans().data ?? [];
  const billingSub = useBillingSubscription(tenantId).data;
  const currentPlan = plans.find(
    (p) => p.price_id === billingSub?.current_price_id,
  );
  const planName = currentPlan?.name ?? "Wardnet Cloud";

  switch (account.lifecycle) {
    case "trial":
      return {
        headline: `Your trial ends in ${daysUntil(account.trialEnd)} days`,
        sentence: `On ${formatDate(account.trialEnd)}, add a payment method to keep dynamic DNS and remote tunneling.`,
        ctaLabel: "Add payment method",
        ctaVariant: "default",
        onCta: toBilling,
        headlineColor: "ink",
      };
    case "active":
      return {
        headline: `${planName} · renews on ${formatDate(account.periodEnd)}`,
        sentence: currentPlan
          ? `${formatPlanPrice(currentPlan)} is charged automatically. You can change or cancel anytime.`
          : "Charged automatically. You can change or cancel anytime.",
        ctaLabel: "Manage subscription",
        ctaVariant: "ghost",
        onCta: toBilling,
        headlineColor: "ink",
      };
    case "grace":
      return {
        headline: `Your subscription expired on ${formatDate(account.periodEnd)}`,
        sentence: `You have ${daysUntil(addDays(account.periodEnd, 7))} days to renew before it's cancelled and premium features stop.`,
        ctaLabel: "Renew now",
        ctaVariant: "default",
        onCta: toBilling,
        headlineColor: "warn",
      };
    case "cancelled":
      return {
        headline: `Cancelled on ${formatDate(account.periodEnd)}`,
        sentence:
          "Reactivate to restore your networks and devices and turn premium features back on.",
        ctaLabel: "Reactivate",
        ctaVariant: "default",
        onCta: toBilling,
        headlineColor: "ink-3",
      };
  }
}

function addDays(date: Date | null, days: number): Date | null {
  return date ? new Date(date.getTime() + days * 86_400_000) : null;
}

function StatusCard({ account }: { account: AccountState }) {
  const content = useStatusContent(account);
  return (
    <Card className={s.statusCard}>
      <div className={s.statusInner}>
        <span
          className={s.stripe}
          style={{ background: account.stripeColor }}
          aria-hidden
        />
        <div className={s.statusBody}>
          <div className={s.statusLabelRow}>
            <Text variant="micro" color="ink-3">
              WARDNET CLOUD
            </Text>
            <Pill variant={account.pillVariant}>{account.statusLabel}</Pill>
          </div>
          <Text variant="body-strong" size="lg" color={content.headlineColor}>
            {content.headline}
          </Text>
          <Text variant="caption" color="ink-2">
            {content.sentence}
          </Text>
          <div className={s.statusCta}>
            <Button variant={content.ctaVariant} size="sm" onClick={content.onCta}>
              {content.ctaLabel}
            </Button>
          </div>
        </div>
      </div>
    </Card>
  );
}

export function Overview() {
  const { account, tenantId } = useAccount();
  const networksQuery = useNetworks(tenantId);
  const daemonsQuery = useDaemons(tenantId);

  return (
    <div className={layout.stack}>
      <div className={layout.pageHead}>
        <Heading level={1}>Overview</Heading>
        <Text variant="body" color="ink-2">
          A snapshot of your Wardnet Cloud account.
        </Text>
      </div>

      <StatusCard account={account} />

      <QueryStates result={daemonsQuery} skeleton={null}>
        {(daemons) => (
          <QueryStates result={networksQuery}>
            {(networks) => {
              const netUsage = computeUsage(
                networks.length,
                account.entitlement.max_networks,
              );
              const devUsage = computeUsage(
                daemons.length,
                account.entitlement.max_daemons,
              );
              const devicesByNetwork = new Map<string, number>();
              for (const d of daemons) {
                devicesByNetwork.set(
                  d.network_id,
                  (devicesByNetwork.get(d.network_id) ?? 0) + 1,
                );
              }
              return (
                <>
                  <div className={s.tiles}>
                    <StatTile
                      label="NETWORKS"
                      value={netUsage.used}
                      unit={`/ ${netUsage.max}`}
                      bar={netUsage.pct}
                      sub={`${Math.max(0, netUsage.remaining)} network slot${netUsage.remaining === 1 ? "" : "s"} remaining`}
                      pill={
                        netUsage.nearLimit ? (
                          <Pill variant="warn">Near limit</Pill>
                        ) : undefined
                      }
                    />
                    <StatTile
                      label="DEVICES"
                      value={devUsage.used}
                      unit={`/ ${devUsage.max}`}
                      bar={devUsage.pct}
                      sub={
                        devUsage.nearLimit
                          ? `Only ${Math.max(0, devUsage.remaining)} device slot left`
                          : `${devUsage.remaining} devices remaining`
                      }
                      pill={
                        devUsage.nearLimit ? (
                          <Pill variant="warn">Near limit</Pill>
                        ) : undefined
                      }
                    />
                  </div>

                  <Card>
                    <CardHeader>
                      <CardTitle>Your networks</CardTitle>
                      <CardSubtitle>
                        {networks.length} of {account.entitlement.max_networks}{" "}
                        network slots in use.
                      </CardSubtitle>
                      {account.isPremiumPaused && (
                        <CardAction>
                          <Pill variant="ghost">Premium paused</Pill>
                        </CardAction>
                      )}
                    </CardHeader>
                    <CardContent>
                      {networks.length === 0 ? (
                        <EmptyState
                          icon={<Network size={18} aria-hidden />}
                          title="No networks yet"
                          description="Networks are created automatically when you install and pair a Wardnet gateway on your Raspberry Pi."
                        />
                      ) : (
                        networks.map((n) => {
                          const status = networkStatus(n.provisioning_state);
                          const count = devicesByNetwork.get(n.id) ?? 0;
                          return (
                            <div key={n.id} className={s.networkRow}>
                              <div className={s.networkMeta}>
                                <Text variant="body" className={s.networkName}>
                                  {n.slug}
                                </Text>
                                <Text variant="caption" color="ink-3">
                                  {n.region}
                                </Text>
                              </div>
                              <Text variant="caption" color="ink-3">
                                {count} devices
                              </Text>
                              <Pill variant={status.variant}>{status.label}</Pill>
                            </div>
                          );
                        })
                      )}
                    </CardContent>
                  </Card>
                </>
              );
            }}
          </QueryStates>
        )}
      </QueryStates>
    </div>
  );
}
