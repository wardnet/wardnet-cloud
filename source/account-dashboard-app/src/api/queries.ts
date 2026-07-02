import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryResult,
} from "@tanstack/react-query";
import {
  cancelSubscription,
  changePlan,
  createCheckoutSession,
  disconnectIdentity,
  getBillingSubscription,
  getDaemons,
  getIdentities,
  getInvoices,
  getMe,
  getNetworks,
  getPaymentMethod,
  getPlans,
  signOutAllSessions,
  startCardUpdate,
} from "./account";
import type {
  BillingSubscriptionView,
  ChangePlanRequest,
  ConnectedIdentityView,
  CreateCheckoutSessionRequest,
  DaemonView,
  IdentityProvider,
  InvoiceView,
  MeView,
  NetworkView,
  PaymentMethodView,
} from "./contract";

export const queryKeys = {
  me: ["me"] as const,
  networks: (tenantId: string) => ["networks", tenantId] as const,
  daemons: (tenantId: string) => ["daemons", tenantId] as const,
  paymentMethod: (tenantId: string) => ["payment-method", tenantId] as const,
  invoices: (tenantId: string) => ["invoices", tenantId] as const,
  identities: ["identities"] as const,
  plans: ["plans"] as const,
  billingSubscription: (tenantId: string) =>
    ["billing-subscription", tenantId] as const,
};

export const useMe = (): UseQueryResult<MeView> =>
  useQuery({ queryKey: queryKeys.me, queryFn: getMe });

export const useNetworks = (tenantId: string): UseQueryResult<NetworkView[]> =>
  useQuery({
    queryKey: queryKeys.networks(tenantId),
    queryFn: () => getNetworks(tenantId),
  });

export const useDaemons = (tenantId: string): UseQueryResult<DaemonView[]> =>
  useQuery({
    queryKey: queryKeys.daemons(tenantId),
    queryFn: () => getDaemons(tenantId),
  });

export const usePaymentMethod = (
  tenantId: string,
): UseQueryResult<PaymentMethodView | null> =>
  useQuery({
    queryKey: queryKeys.paymentMethod(tenantId),
    queryFn: () => getPaymentMethod(tenantId),
  });

export const useInvoices = (tenantId: string): UseQueryResult<InvoiceView[]> =>
  useQuery({
    queryKey: queryKeys.invoices(tenantId),
    queryFn: () => getInvoices(tenantId),
  });

/** The public plan catalog (cached a while; it changes rarely). */
export const usePlans = () =>
  useQuery({ queryKey: queryKeys.plans, queryFn: getPlans, staleTime: 60_000 });

export const useBillingSubscription = (tenantId: string) =>
  useQuery({
    queryKey: queryKeys.billingSubscription(tenantId),
    queryFn: () => getBillingSubscription(tenantId),
  });

export const useIdentities = (): UseQueryResult<ConnectedIdentityView[]> =>
  useQuery({ queryKey: queryKeys.identities, queryFn: getIdentities });

/** Redirect the browser to the Stripe-hosted Checkout for the given price. */
export const useCheckout = (tenantId: string) =>
  useMutation({
    mutationFn: (body: CreateCheckoutSessionRequest) =>
      createCheckoutSession(tenantId, body),
    onSuccess: ({ url }) => {
      window.location.assign(url);
    },
  });

/** Redirect the browser to the Stripe-hosted setup-mode Checkout to update the card. */
export const useCardUpdate = (tenantId: string) =>
  useMutation({
    mutationFn: () => startCardUpdate(tenantId),
    onSuccess: ({ url }) => {
      window.location.assign(url);
    },
  });

/** Change plan in-app (upgrade now / downgrade at period end). Entitlement lands via
 *  the webhook, so refetch `me`. For the billing subscription, reflect an upgrade
 *  immediately from the response — the webhook that back-fills `billing_customers` lags,
 *  so a refetch would briefly show the old plan (the post-upgrade UI-lag bug). A
 *  downgrade leaves the current price unchanged and its pending change is a live Stripe
 *  read (no lag), so there we refetch to pick up / clear the banner. */
export const useChangePlan = (tenantId: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ChangePlanRequest) => changePlan(tenantId, body),
    onSuccess: (data) => {
      void qc.invalidateQueries({ queryKey: queryKeys.me });
      const key = queryKeys.billingSubscription(tenantId);
      const cached = qc.getQueryData<BillingSubscriptionView>(key);
      if (data.effect === "upgraded" && cached) {
        // Reflect the upgrade at once (the webhook that back-fills billing_customers lags).
        // An upgrade also ends any honored Stripe trial, so clear `trialing`, and releases
        // any pending downgrade (release-then-act).
        qc.setQueryData<BillingSubscriptionView>(key, {
          ...cached,
          current_price_id: data.current_price_id,
          trialing: false,
          pending_change: null,
        });
      } else {
        // Downgrade/cancel (pending change is a live Stripe read, no lag), or an upgrade
        // with a cold/evicted cache (nothing to patch) — refetch.
        void qc.invalidateQueries({ queryKey: key });
      }
    },
  });
};

export const useCancelSubscription = (tenantId: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => cancelSubscription(tenantId),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.me }),
  });
};

export const useDisconnectIdentity = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (provider: IdentityProvider) => disconnectIdentity(provider),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.identities }),
  });
};

export const useSignOutAll = () =>
  useMutation({ mutationFn: signOutAllSessions });
