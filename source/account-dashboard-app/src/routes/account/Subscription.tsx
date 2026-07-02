import * as React from "react";
import { useSearchParams } from "react-router-dom";
import { CreditCard, Download } from "lucide-react";
import {
  AlertModal,
  AlertModalAction,
  AlertModalBody,
  AlertModalCancel,
  AlertModalContent,
  AlertModalDescription,
  AlertModalFooter,
  AlertModalHeader,
  AlertModalTitle,
  AlertModalTrigger,
  Banner,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardSubtitle,
  CardTitle,
  Heading,
  Meter,
  Pill,
  Text,
  toast,
} from "@wardnet/ui";
import {
  useBillingSubscription,
  useCancelSubscription,
  useCardUpdate,
  useChangePlan,
  useCheckout,
  useDaemons,
  useInvoices,
  useNetworks,
  usePaymentMethod,
  usePlans,
} from "../../api/queries";
import { ApiError, PromoUnavailableError } from "../../api/client";
import type { AccountState } from "../../account/spine";
import { computeUsage } from "../../account/spine";
import type {
  InvoiceView,
  PaymentMethodView,
  PendingChangeView,
  PlanView,
} from "../../api/contract";
import { CardSkeleton, QueryStates } from "../../components/feedback";
import {
  daysUntil,
  formatDate,
  formatExpiry,
  formatMoney,
  titleCase,
} from "../../lib/format";
import { effectiveAmountCents, formatPlanPrice, intervalLabel } from "../../lib/plan";
import { DEMO_ENABLED } from "../../config/env";
import { useAccount } from "./AccountContext";
import layout from "./AccountLayout.module.css";
import s from "./Subscription.module.css";

/** A confirm prompt shown when a displayed promo lapsed at apply time (ADR-0011). */
interface PromoConfirm {
  actualAmountCents: number;
  currency: string;
  retry: (acceptFullPrice: boolean) => void;
}

/** Inline price with a strike-through list price when a promo is live. */
function PlanPrice({ plan }: { plan: PlanView }) {
  return (
    <span className={s.planPrice}>
      {plan.promo && (
        <Text variant="caption" className={s.strike}>
          {formatMoney(plan.amount_cents, plan.currency)}
        </Text>
      )}
      <Text variant="body-strong">
        {formatMoney(effectiveAmountCents(plan), plan.currency)}
      </Text>
      <Text variant="caption" color="ink-3">
        / {intervalLabel(plan.interval)}
      </Text>
    </span>
  );
}

function PlanCard({
  account,
  plan,
}: {
  account: AccountState;
  plan: PlanView | undefined;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Wardnet {plan?.name ?? "Cloud"}</CardTitle>
        <CardSubtitle>
          Premium gateway features for self-hosted Wardnet.
        </CardSubtitle>
      </CardHeader>
      <CardContent>
        <div className={s.priceRow}>
          {plan ? (
            <PlanPrice plan={plan} />
          ) : (
            <Text variant="body" color="ink-3">
              See plans below.
            </Text>
          )}
          <span style={{ flex: 1 }} />
          <Pill variant={account.pillVariant}>{account.statusLabel}</Pill>
        </div>
        <Text variant="caption" color="ink-3">
          billed {plan ? `${intervalLabel(plan.interval)}.` : "monthly ·"} cancel
          anytime
        </Text>
      </CardContent>
    </Card>
  );
}

function EntitlementMeter({
  label,
  used,
  max,
}: {
  label: string;
  used: number;
  max: number;
}) {
  const usage = computeUsage(used, max);
  return (
    <div className={s.meterRow}>
      <div className={s.meterHead}>
        <Text variant="body">{label}</Text>
        <Text variant="caption" color={usage.nearLimit ? "warn" : "ink-3"}>
          {used} of {max}
        </Text>
      </div>
      <Meter value={used} max={max} tone={usage.tone} />
    </div>
  );
}

function EntitlementsCard({
  account,
  networksUsed,
  devicesUsed,
}: {
  account: AccountState;
  networksUsed: number;
  devicesUsed: number;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Entitlements</CardTitle>
        <CardSubtitle>
          What your plan grants, and how much you&apos;re using.
        </CardSubtitle>
      </CardHeader>
      <CardContent>
        <EntitlementMeter
          label="Networks"
          used={networksUsed}
          max={account.entitlement.max_networks}
        />
        <EntitlementMeter
          label="Devices"
          used={devicesUsed}
          max={account.entitlement.max_daemons}
        />
      </CardContent>
    </Card>
  );
}

/** The catalog picker. Active subscribers upgrade/downgrade; everyone else subscribes. */
function PlanPicker({
  plans,
  currentPlan,
  isPaid,
  onChoose,
  onChange,
}: {
  plans: PlanView[];
  currentPlan: PlanView | undefined;
  isPaid: boolean;
  onChoose: (priceId: string) => void;
  onChange: (priceId: string) => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Plans</CardTitle>
        <CardSubtitle>
          {isPaid
            ? "Upgrade takes effect immediately; a downgrade applies at your next renewal."
            : "Choose a plan to subscribe."}
        </CardSubtitle>
      </CardHeader>
      <CardContent>
        <div className={s.planList}>
          {plans.map((plan) => {
            const isCurrent = plan.price_id === currentPlan?.price_id;
            return (
              <div
                key={plan.price_id}
                className={`${s.planRow} ${isCurrent ? s.planRowCurrent : ""}`}
              >
                <div className={s.planMeta}>
                  <Text variant="body-strong">{plan.name}</Text>
                  <Text variant="caption" color="ink-3">
                    {plan.entitlement.max_networks} networks ·{" "}
                    {plan.entitlement.max_daemons} devices
                  </Text>
                </div>
                <PlanPrice plan={plan} />
                {isCurrent ? (
                  <Pill variant="ok">Current</Pill>
                ) : isPaid && currentPlan ? (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onChange(plan.price_id)}
                  >
                    {plan.level > currentPlan.level ? "Upgrade" : "Downgrade"}
                  </Button>
                ) : (
                  <Button size="sm" onClick={() => onChoose(plan.price_id)}>
                    Choose
                  </Button>
                )}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

/** "Downgrades to X on DATE" with an option to cancel the pending change. */
function PendingDowngradeBanner({
  pending,
  onKeepCurrent,
}: {
  pending: PendingChangeView;
  onKeepCurrent: () => void;
}) {
  return (
    <Banner
      tone="info"
      role="status"
      actions={
        <Button variant="ghost" size="sm" onClick={onKeepCurrent}>
          Keep current plan
        </Button>
      }
    >
      Your plan downgrades to {pending.name} on {formatDate(pending.effective_at)}.
    </Banner>
  );
}

function LifecycleCard({
  account,
  currentPlan,
  subscribePriceId,
  openInvoiceUrl,
  onSubscribe,
  onUpdateCard,
  onCancel,
}: {
  account: AccountState;
  currentPlan: PlanView | undefined;
  subscribePriceId: string | null;
  openInvoiceUrl: string | null;
  onSubscribe: (priceId: string) => void;
  onUpdateCard: () => void;
  onCancel: () => void;
}) {
  const subscribe = () => {
    if (subscribePriceId) onSubscribe(subscribePriceId);
  };

  switch (account.lifecycle) {
    case "trial":
      return (
        <Card>
          <CardHeader>
            <CardTitle>Trial</CardTitle>
          </CardHeader>
          <CardContent>
            <Text variant="body" color="ink-2">
              Your trial ends in {daysUntil(account.trialEnd)} days (
              {formatDate(account.trialEnd)}).
            </Text>
            <Text variant="caption" color="ink-3">
              Add a payment method to upgrade and keep Wardnet Cloud running
              without interruption.
            </Text>
            <div className={s.lifecycleActions}>
              <Button size="sm" onClick={subscribe} disabled={!subscribePriceId}>
                Add payment method
              </Button>
            </div>
          </CardContent>
        </Card>
      );
    case "active":
      return (
        <Card>
          <CardHeader>
            <CardTitle>Billing</CardTitle>
          </CardHeader>
          <CardContent>
            <Text variant="body" color="ink-2">
              Renews on {formatDate(account.periodEnd)}.
            </Text>
            <Text variant="caption" color="ink-3">
              {currentPlan
                ? `${formatPlanPrice(currentPlan)} will be charged automatically. `
                : ""}
              Change your plan above, or update your card below.
            </Text>
            <div className={s.lifecycleActions}>
              <Button variant="ghost" size="sm" onClick={onUpdateCard}>
                Update payment method
              </Button>
              <CancelModal
                onConfirm={onCancel}
                periodEnd={account.periodEnd}
                planName={currentPlan?.name}
              />
            </div>
          </CardContent>
        </Card>
      );
    case "grace":
      return (
        <Card>
          <CardHeader>
            <CardTitle>Renew to restore premium features</CardTitle>
          </CardHeader>
          <CardContent>
            <Text variant="body" color="ink-2">
              Your subscription expired on {formatDate(account.periodEnd)}. After
              the grace period, dynamic DNS and remote tunneling switch off and
              your account is cancelled.
            </Text>
            <div className={s.lifecycleActions}>
              {openInvoiceUrl ? (
                <Button size="sm" asChild>
                  <a href={openInvoiceUrl} target="_blank" rel="noreferrer">
                    Pay now
                  </a>
                </Button>
              ) : (
                <Button size="sm" onClick={subscribe} disabled={!subscribePriceId}>
                  Renew now
                </Button>
              )}
              <Button variant="ghost" size="sm" onClick={onUpdateCard}>
                Update payment method
              </Button>
            </div>
          </CardContent>
        </Card>
      );
    case "cancelled":
      return (
        <Card>
          <CardHeader>
            <CardTitle>Subscription cancelled</CardTitle>
          </CardHeader>
          <CardContent>
            <Text variant="body" color="ink-2">
              Cancelled on {formatDate(account.periodEnd)}. Your networks and
              devices are retained for 30 days. Choose a plan above to restore them
              and turn premium features back on.
            </Text>
          </CardContent>
        </Card>
      );
  }
}

function CancelModal({
  onConfirm,
  periodEnd,
  planName,
}: {
  onConfirm: () => void;
  periodEnd: Date | null;
  planName?: string;
}) {
  return (
    <AlertModal>
      <AlertModalTrigger asChild>
        <Button variant="destructive" size="sm">
          Cancel subscription
        </Button>
      </AlertModalTrigger>
      <AlertModalContent>
        <AlertModalHeader>
          <AlertModalTitle>
            Cancel your {planName ?? "Wardnet Cloud"} subscription?
          </AlertModalTitle>
        </AlertModalHeader>
        <AlertModalBody>
          <AlertModalDescription>
            Your plan stays active until {formatDate(periodEnd)}, then premium
            features switch off. Networks beyond the free limit (1 network, 5
            devices) and remote tunneling will be disabled until you resubscribe.
          </AlertModalDescription>
        </AlertModalBody>
        <AlertModalFooter>
          <AlertModalCancel asChild>
            <Button variant="ghost" size="sm">
              Keep subscription
            </Button>
          </AlertModalCancel>
          <AlertModalAction asChild>
            <Button variant="destructive" size="sm" onClick={onConfirm}>
              Cancel at period end
            </Button>
          </AlertModalAction>
        </AlertModalFooter>
      </AlertModalContent>
    </AlertModal>
  );
}

/** Open when a promo lapsed at apply time: confirm the real price or back out. */
function PromoConfirmModal({
  confirm,
  onDismiss,
}: {
  confirm: PromoConfirm | null;
  onDismiss: () => void;
}) {
  return (
    <AlertModal open={confirm !== null} onOpenChange={(o) => !o && onDismiss()}>
      <AlertModalContent>
        <AlertModalHeader>
          <AlertModalTitle>This promotion has ended</AlertModalTitle>
        </AlertModalHeader>
        <AlertModalBody>
          <AlertModalDescription>
            {confirm &&
              `The price is now ${formatMoney(
                confirm.actualAmountCents,
                confirm.currency,
              )}. Continue at the full price?`}
          </AlertModalDescription>
        </AlertModalBody>
        <AlertModalFooter>
          <AlertModalCancel asChild>
            <Button variant="ghost" size="sm" onClick={onDismiss}>
              Not now
            </Button>
          </AlertModalCancel>
          <AlertModalAction asChild>
            <Button
              size="sm"
              onClick={() => confirm?.retry(true)}
            >
              Continue
            </Button>
          </AlertModalAction>
        </AlertModalFooter>
      </AlertModalContent>
    </AlertModal>
  );
}

/** Confirm a trial-ending subscribe, naming the free days being forfeited (ADR-0012). */
function TrialForfeitModal({
  forfeit,
  trialDaysLeft,
  onConfirm,
  onDismiss,
}: {
  forfeit: { planName: string } | null;
  trialDaysLeft: number | null;
  onConfirm: () => void;
  onDismiss: () => void;
}) {
  const daysLeft =
    trialDaysLeft !== null && trialDaysLeft > 0
      ? ` You have ${trialDaysLeft} ${trialDaysLeft === 1 ? "day" : "days"} of trial left.`
      : "";
  return (
    <AlertModal open={forfeit !== null} onOpenChange={(o) => !o && onDismiss()}>
      <AlertModalContent>
        <AlertModalHeader>
          <AlertModalTitle>End your free trial?</AlertModalTitle>
        </AlertModalHeader>
        <AlertModalBody>
          <AlertModalDescription>
            {forfeit &&
              `Switching to ${forfeit.planName} ends your free trial now and starts billing today.${daysLeft}`}
          </AlertModalDescription>
        </AlertModalBody>
        <AlertModalFooter>
          <AlertModalCancel asChild>
            <Button variant="ghost" size="sm" onClick={onDismiss}>
              Keep my trial
            </Button>
          </AlertModalCancel>
          <AlertModalAction asChild>
            <Button size="sm" onClick={onConfirm}>
              Subscribe now
            </Button>
          </AlertModalAction>
        </AlertModalFooter>
      </AlertModalContent>
    </AlertModal>
  );
}

function PaymentMethodCard({
  paymentMethod,
  showAdd,
  onAdd,
  onUpdate,
}: {
  paymentMethod: PaymentMethodView | null;
  showAdd: boolean;
  onAdd: () => void;
  onUpdate: () => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Payment method</CardTitle>
        <CardSubtitle>Used for renewals and any upgrades.</CardSubtitle>
      </CardHeader>
      <CardContent>
        {paymentMethod ? (
          <div className={s.pmRow}>
            <span className={s.pmIcon}>
              <CreditCard size={18} aria-hidden />
            </span>
            <div className={s.pmMeta}>
              <Text variant="body-strong">
                {titleCase(paymentMethod.brand)} •••• {paymentMethod.last4}
              </Text>
              <Text variant="caption" color="ink-3">
                Expires{" "}
                {formatExpiry(paymentMethod.exp_month, paymentMethod.exp_year)}
              </Text>
            </div>
            <Button variant="ghost" size="sm" onClick={onUpdate}>
              Update
            </Button>
          </div>
        ) : (
          <div className={s.pmRow}>
            <Text variant="body" color="ink-3">
              No payment method on file.
            </Text>
            <span style={{ flex: 1 }} />
            {showAdd && (
              <Button size="sm" onClick={onAdd}>
                Add payment method
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

const STATUS_PILL: Record<InvoiceView["status"], "ok" | "info" | "warn" | "down"> =
  {
    paid: "ok",
    open: "info",
    void: "warn",
    uncollectible: "down",
  };

function BillingHistoryCard({ invoices }: { invoices: InvoiceView[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Billing history</CardTitle>
        <CardSubtitle>Receipts for your Wardnet Cloud subscription.</CardSubtitle>
      </CardHeader>
      <CardContent>
        {invoices.length === 0 ? (
          <Text variant="body" color="ink-3">
            No invoices yet.
          </Text>
        ) : (
          <div className={s.table}>
            <div className={s.tableHead}>
              <Text variant="micro" color="ink-3">
                DATE
              </Text>
              <Text variant="micro" color="ink-3">
                AMOUNT
              </Text>
              <Text variant="micro" color="ink-3">
                STATUS
              </Text>
              <Text variant="micro" color="ink-3">
                INVOICE
              </Text>
            </div>
            {invoices.map((inv) => (
              <div key={inv.date + inv.amount_cents} className={s.tableRow}>
                <Text variant="body">{formatDate(inv.date)}</Text>
                <Text variant="body" className={s.amount}>
                  {formatMoney(inv.amount_cents, inv.currency)}
                </Text>
                <span>
                  <Pill variant={STATUS_PILL[inv.status]}>
                    {titleCase(inv.status)}
                  </Pill>
                </span>
                <span>
                  {inv.hosted_url && (
                    <a
                      className={s.iconBtn}
                      href={inv.hosted_url}
                      target="_blank"
                      rel="noreferrer"
                      aria-label="Download invoice"
                    >
                      <Download size={16} aria-hidden />
                    </a>
                  )}
                </span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function Subscription() {
  const { account, tenantId } = useAccount();
  const networksQuery = useNetworks(tenantId);
  const daemonsQuery = useDaemons(tenantId);
  const paymentQuery = usePaymentMethod(tenantId);
  const invoicesQuery = useInvoices(tenantId);
  const plansQuery = usePlans();
  const billingSubQuery = useBillingSubscription(tenantId);
  const checkout = useCheckout(tenantId);
  const changePlan = useChangePlan(tenantId);
  const cardUpdate = useCardUpdate(tenantId);
  const cancel = useCancelSubscription(tenantId);

  const [promoConfirm, setPromoConfirm] = React.useState<PromoConfirm | null>(
    null,
  );
  // A trial-ending change awaiting confirmation (ADR-0012): the user picked a plan above
  // the trial's entitlement, which forfeits their remaining free days — either a subscribe
  // from the managed trial or an in-app upgrade of a honored (Stripe) trial.
  const [trialForfeit, setTrialForfeit] = React.useState<{
    planName: string;
    run: () => void;
  } | null>(null);

  const networksUsed = networksQuery.data?.length ?? 0;
  const devicesUsed = daemonsQuery.data?.length ?? 0;

  const plans = plansQuery.data ?? [];
  const billingSub = billingSubQuery.data;
  const isPaid = account.lifecycle === "active" || account.lifecycle === "grace";
  const currentPlan = plans.find(
    (p) => p.price_id === billingSub?.current_price_id,
  );
  const entryPlan = plans[0];
  // The current Stripe price from Billing (billing_customers) — authoritative even if the
  // catalog projection has dropped/archived that price, so renew/keep never silently
  // downgrades onto the entry plan.
  const currentPriceId = billingSub?.current_price_id ?? null;
  // What "subscribe/renew" targets: the current price when there is one (grace/active),
  // else the entry plan (trial/cancelled).
  const subscribePriceId = currentPriceId ?? entryPlan?.price_id ?? null;
  const openInvoiceUrl =
    invoicesQuery.data?.find((i) => i.status === "open" && i.hosted_url)
      ?.hosted_url ?? null;

  // Run a checkout/change that may hit a lapsed-promo 409; on that, prompt to
  // re-confirm at full price (re-calls with accept_full_price = true).
  const guard = (run: (acceptFullPrice: boolean) => Promise<unknown>) => {
    run(false).catch((e: unknown) => {
      if (e instanceof PromoUnavailableError) {
        setPromoConfirm({
          actualAmountCents: e.actualAmountCents,
          currency: e.currency,
          retry: (acceptFullPrice) => {
            setPromoConfirm(null);
            void run(acceptFullPrice);
          },
        });
        return;
      }
      // Surface an expected client error (e.g. 400 "already on this plan" / "no paid
      // subscription") so the button isn't a silent no-op. 401 (re-auth) and 5xx/network
      // are already handled centrally by apiFetch.
      if (e instanceof ApiError && e.status >= 400 && e.status < 500) {
        toast.error("That change couldn't be applied. Please try again.");
      }
    });
  };

  const subscribe = (priceId: string) =>
    guard((acceptFullPrice) =>
      checkout.mutateAsync({ price_id: priceId, accept_full_price: acceptFullPrice }),
    );
  // Choosing a plan from the trial: a plan above the trial's entitlement forfeits the
  // remaining free days, so confirm first (ADR-0012); the trial-equivalent plan (Home)
  // is preserved server-side and subscribes seamlessly.
  const choose = (priceId: string) => {
    const plan = plans.find((p) => p.price_id === priceId);
    const forfeitsTrial =
      account.lifecycle === "trial" &&
      !!plan &&
      (plan.entitlement.max_networks > account.entitlement.max_networks ||
        plan.entitlement.max_daemons > account.entitlement.max_daemons);
    if (plan && forfeitsTrial) {
      setTrialForfeit({ planName: plan.name, run: () => subscribe(priceId) });
    } else {
      subscribe(priceId);
    }
  };
  const change = (priceId: string) =>
    guard((acceptFullPrice) =>
      changePlan.mutateAsync({
        price_id: priceId,
        accept_full_price: acceptFullPrice,
      }),
    );
  // Any change to a subscription still in its Stripe trial ends the trial and charges now
  // (ADR-0012), so confirm first. A honored trial always sits on Home (the floor), so the
  // picker only ever offers upgrades from it — we gate purely on `billingSub.trialing` and
  // never on the catalog-derived `currentPlan` (which can be undefined if the projection
  // dropped the current price), so the confirmation is never silently skipped.
  const changeGuarded = (priceId: string) => {
    const plan = plans.find((p) => p.price_id === priceId);
    if (billingSub?.trialing && plan) {
      setTrialForfeit({ planName: plan.name, run: () => change(priceId) });
    } else {
      change(priceId);
    }
  };
  const keepCurrentPlan = () => {
    // Cancel the pending downgrade by re-selecting the current price. Use the
    // authoritative billing price id, not the catalog-derived currentPlan (which may be
    // absent if the projection dropped that price), so the button is never a no-op.
    if (currentPriceId) change(currentPriceId);
  };

  const [searchParams, setSearchParams] = useSearchParams();
  const billingReturn = DEMO_ENABLED ? searchParams.get("billing") : null;
  const dismissBillingReturn = () => {
    setSearchParams(
      (prev) => {
        prev.delete("billing");
        return prev;
      },
      { replace: true },
    );
  };

  return (
    <div className={layout.stack}>
      <div className={layout.pageHead}>
        <Heading level={1}>Subscription</Heading>
        <Text variant="body" color="ink-2">
          Manage your plan, billing, and entitlements.
        </Text>
      </div>

      {billingReturn && (
        <Banner
          tone="info"
          role="status"
          actions={
            <Button variant="ghost" size="sm" onClick={dismissBillingReturn}>
              Dismiss
            </Button>
          }
        >
          Demo mode: in production this opens Stripe-hosted Checkout and returns
          you here afterwards.
        </Banner>
      )}

      {billingSub?.pending_change && (
        <PendingDowngradeBanner
          pending={billingSub.pending_change}
          onKeepCurrent={keepCurrentPlan}
        />
      )}

      {account.lifecycle === "grace" && (
        <Banner
          tone="down"
          role="alert"
          actions={
            openInvoiceUrl ? (
              <Button size="sm" asChild>
                <a href={openInvoiceUrl} target="_blank" rel="noreferrer">
                  Pay now
                </a>
              </Button>
            ) : (
              <Button
                size="sm"
                onClick={() => subscribePriceId && subscribe(subscribePriceId)}
                disabled={!subscribePriceId}
              >
                Renew now
              </Button>
            )
          }
        >
          Your subscription expired on {formatDate(account.periodEnd)}. You have{" "}
          {daysUntil(
            account.periodEnd
              ? new Date(account.periodEnd.getTime() + 7 * 86_400_000)
              : null,
          )}{" "}
          days to renew before it&apos;s cancelled and premium features stop.
        </Banner>
      )}

      <div className={s.topGrid}>
        <PlanCard account={account} plan={currentPlan ?? entryPlan} />
        <EntitlementsCard
          account={account}
          networksUsed={networksUsed}
          devicesUsed={devicesUsed}
        />
      </div>

      <LifecycleCard
        account={account}
        currentPlan={currentPlan}
        subscribePriceId={subscribePriceId}
        openInvoiceUrl={openInvoiceUrl}
        onSubscribe={subscribe}
        onUpdateCard={() => cardUpdate.mutate()}
        onCancel={() => cancel.mutate()}
      />

      <QueryStates result={plansQuery} skeleton={<CardSkeleton lines={3} />}>
        {(catalog) => (
          <PlanPicker
            plans={catalog}
            currentPlan={currentPlan}
            isPaid={isPaid}
            onChoose={choose}
            onChange={changeGuarded}
          />
        )}
      </QueryStates>

      <QueryStates result={paymentQuery} skeleton={<CardSkeleton lines={1} />}>
        {(paymentMethod) => (
          <PaymentMethodCard
            paymentMethod={paymentMethod}
            showAdd={account.lifecycle === "trial"}
            onAdd={() => subscribePriceId && subscribe(subscribePriceId)}
            onUpdate={() => cardUpdate.mutate()}
          />
        )}
      </QueryStates>

      <QueryStates result={invoicesQuery}>
        {(invoices) => <BillingHistoryCard invoices={invoices} />}
      </QueryStates>

      <PromoConfirmModal
        confirm={promoConfirm}
        onDismiss={() => setPromoConfirm(null)}
      />

      <TrialForfeitModal
        forfeit={trialForfeit}
        trialDaysLeft={account.trialEnd ? daysUntil(account.trialEnd) : null}
        onConfirm={() => {
          const chosen = trialForfeit;
          setTrialForfeit(null);
          chosen?.run();
        }}
        onDismiss={() => setTrialForfeit(null)}
      />
    </div>
  );
}
