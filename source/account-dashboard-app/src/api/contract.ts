// Wire types mirroring `wardnet_common::contract` (the backend's shared DTOs).
// Keep these in lock-step with `source/crates/common/src/contract.rs`.

export type SubscriptionStatus =
  | "trialing"
  | "active"
  | "past_due"
  | "canceled";

export interface Entitlement {
  max_networks: number;
  max_daemons: number;
}

export interface SubscriptionView {
  id: string;
  status: SubscriptionStatus;
  entitlement: Entitlement;
  trial_expires_at: string | null;
  current_period_end: string | null;
  created_at: string;
  updated_at: string;
}

export interface MeView {
  tenant_id: string;
  email: string;
  subscription: SubscriptionView | null;
}

export type ProvisioningState = "provisioning" | "active" | "deprovisioning";

export interface NetworkView {
  id: string;
  tenant_id: string;
  slug: string;
  display_name: string;
  region: string;
  provisioning_state: ProvisioningState;
  created_at: string;
  updated_at: string;
}

export interface DaemonView {
  id: string;
  network_id: string;
  public_key: string;
  created_at: string;
}

export interface PaymentMethodView {
  brand: string;
  last4: string;
  exp_month: number;
  exp_year: number;
}

export type InvoiceStatus = "paid" | "open" | "void" | "uncollectible";

export interface InvoiceView {
  date: string;
  amount_cents: number;
  currency: string;
  status: InvoiceStatus;
  hosted_url: string | null;
}

export type IdentityProvider = "password" | "google" | "github";

export interface ConnectedIdentityView {
  provider: IdentityProvider;
  label: string;
  connected_at: string;
}

export interface CheckoutSessionResponse {
  url: string;
}

/** A live promotion on a {@link PlanView} (display-only; applied server-side). */
export interface PromoView {
  amount_cents_after: number;
  label: string;
  ends_at: string;
}

/** One purchasable plan from `GET /v1/plans` (ascending by `level`). */
export interface PlanView {
  price_id: string;
  name: string;
  level: number;
  entitlement: Entitlement;
  amount_cents: number;
  currency: string;
  interval: string;
  promo: PromoView | null;
}

export type PlanChangeEffect =
  | "upgraded"
  | "downgrade_scheduled"
  | "downgrade_canceled";

export interface ChangePlanRequest {
  price_id: string;
  /** Re-confirm at full price after a {@link PromoUnavailableBody} 409. */
  accept_full_price?: boolean;
}

export interface ChangePlanResponse {
  effect: PlanChangeEffect;
  effective_at: string | null;
  /** The price the tenant is on after this change — lets the UI reflect an upgrade
   *  immediately instead of waiting on the async webhook. */
  current_price_id: string | null;
}

/** A pending scheduled plan change (today only a downgrade). */
export interface PendingChangeView {
  price_id: string;
  name: string;
  level: number;
  effective_at: string;
}

/** Provider (Billing) view of the subscription, composed by the SPA with `/v1/me`. */
export interface BillingSubscriptionView {
  current_price_id: string | null;
  pending_change: PendingChangeView | null;
  /** Whether the subscription is still in its Stripe trial (a trial-preserving Home
   *  sub) — the SPA confirms before an in-app upgrade that would end it. */
  trialing: boolean;
}

/** `409` body from checkout / change-plan when a displayed promo lapsed at apply time. */
export interface PromoUnavailableBody {
  error: "promo_unavailable";
  actual_amount_cents: number;
  currency: string;
}

export type CodePurpose =
  | "signup"
  | "password_reset"
  | "password_change"
  | "enrollment";

export interface VerificationCodeRequest {
  email: string;
  purpose: CodePurpose;
}

export interface VerificationCodeResponse {
  /** Present in dev / no-op-email mode; `null` in production. */
  code: string | null;
}

/** Response of `POST /v1/auth/token` — the minted short-TTL USER JWT. */
export interface TokenResponse {
  token: string;
}

export interface PasswordSignupRequest {
  email: string;
  code: string;
  password: string;
}

export interface PasswordLoginRequest {
  email: string;
  password: string;
}

export interface PasswordResetRequest {
  code: string;
  password: string;
}

/** Body of `POST /v1/me/password` — authenticated set/change password. The `code`
 *  is a `password_change` email proof for the caller's own account email. */
export interface SetPasswordRequest {
  code: string;
  password: string;
}

export interface CreateCheckoutSessionRequest {
  price_id: string;
  /** Re-confirm at full price after a {@link PromoUnavailableBody} 409. */
  accept_full_price?: boolean;
}

/** Request body of `PATCH /v1/tenants/{id}` — only `"canceled"` is accepted. */
export interface UpdateTenantRequest {
  subscription_status: "canceled";
}
