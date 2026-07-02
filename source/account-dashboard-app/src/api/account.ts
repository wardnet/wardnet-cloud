import { apiFetch } from "./client";
import type {
  BillingSubscriptionView,
  ChangePlanRequest,
  ChangePlanResponse,
  CheckoutSessionResponse,
  ConnectedIdentityView,
  CreateCheckoutSessionRequest,
  DaemonView,
  IdentityProvider,
  InvoiceView,
  MeView,
  NetworkView,
  PaymentMethodView,
  PlanView,
  UpdateTenantRequest,
} from "./contract";

export const getMe = () => apiFetch<MeView>("/me");

export const getNetworks = (tenantId: string) =>
  apiFetch<NetworkView[]>(`/tenants/${tenantId}/networks`);

export const getDaemons = (tenantId: string) =>
  apiFetch<DaemonView[]>(`/tenants/${tenantId}/daemons`);

export const getPaymentMethod = (tenantId: string) =>
  apiFetch<PaymentMethodView | null>(`/tenants/${tenantId}/billing/payment-method`);

export const getInvoices = (tenantId: string) =>
  apiFetch<InvoiceView[]>(`/tenants/${tenantId}/billing/invoices`);

export const getPlans = () => apiFetch<PlanView[]>("/plans", { anonymous: true });

export const getBillingSubscription = (tenantId: string) =>
  apiFetch<BillingSubscriptionView>(`/tenants/${tenantId}/billing/subscription`);

export const getIdentities = () =>
  apiFetch<ConnectedIdentityView[]>("/me/identities");

export const createCheckoutSession = (
  tenantId: string,
  body: CreateCheckoutSessionRequest,
) =>
  apiFetch<CheckoutSessionResponse>(
    `/tenants/${tenantId}/billing/checkout-session`,
    { method: "POST", body: JSON.stringify(body) },
  );

export const changePlan = (tenantId: string, body: ChangePlanRequest) =>
  apiFetch<ChangePlanResponse>(`/tenants/${tenantId}/billing/change-plan`, {
    method: "POST",
    body: JSON.stringify(body),
  });

export const startCardUpdate = (tenantId: string) =>
  apiFetch<CheckoutSessionResponse>(`/tenants/${tenantId}/billing/card-update`, {
    method: "POST",
  });

export const cancelSubscription = (tenantId: string) =>
  apiFetch<void>(`/tenants/${tenantId}`, {
    method: "PATCH",
    body: JSON.stringify({ subscription_status: "canceled" } satisfies UpdateTenantRequest),
  });

export const disconnectIdentity = (provider: IdentityProvider) =>
  apiFetch<void>(`/me/identities/${provider}`, { method: "DELETE" });

export const signOutAllSessions = () =>
  apiFetch<void>("/me/sessions", { method: "DELETE" });
