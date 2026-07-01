import { delay, http, HttpResponse, type JsonBodyType } from "msw";
import type {
  ChangePlanRequest,
  ChangePlanResponse,
  CheckoutSessionResponse,
  PasswordLoginRequest,
  PasswordSignupRequest,
  TokenResponse,
  VerificationCodeRequest,
} from "../api/contract";
import {
  buildBillingSubscription,
  buildDaemons,
  buildIdentities,
  buildInvoices,
  buildMe,
  buildNetworks,
  buildPaymentMethod,
  buildPlans,
  DEMO_CODE,
  PRICE_PRO,
} from "./db";
import { getScenario } from "./scenario";

// A single in-memory "session cookie" so the auth flow behaves: the silent
// exchange fails until a login/signup/OIDC sets it.
let session = false;
export const setMockSession = (value: boolean) => {
  session = value;
};
// Connected sign-in methods are mutable so the Security page can actually
// disconnect a method in the mock and exercise the "last method must remain" guard.
let identities = buildIdentities();
export const resetMockSession = () => {
  session = false;
  identities = buildIdentities();
};

/** Map the Demo data scenario onto a data response (loading/error/empty/ready). */
async function respondData<T extends JsonBodyType>(
  ready: T,
  empty: T,
): Promise<Response> {
  const { data } = getScenario();
  if (data === "loading") {
    await delay("infinite");
    return HttpResponse.json(ready);
  }
  if (data === "error") {
    return new HttpResponse(null, { status: 500 });
  }
  return HttpResponse.json(data === "empty" ? empty : ready);
}

const sub = () => getScenario().subscription;

export const handlers = [
  // ── Auth ──────────────────────────────────────────────────────────────────
  http.post("/v1/auth/token", () => {
    if (!session) return new HttpResponse(null, { status: 401 });
    return HttpResponse.json<TokenResponse>({ token: "demo.jwt.token" });
  }),
  http.post("/v1/auth/password/login", async ({ request }) => {
    const body = (await request.json()) as PasswordLoginRequest;
    if (!body.email || !body.password) {
      return new HttpResponse(null, { status: 400 });
    }
    session = true;
    return new HttpResponse(null, { status: 204 });
  }),
  http.post("/v1/auth/password/signup", async ({ request }) => {
    const body = (await request.json()) as PasswordSignupRequest;
    if (body.code !== DEMO_CODE) return new HttpResponse(null, { status: 400 });
    session = true;
    return new HttpResponse(null, { status: 204 });
  }),
  http.post("/v1/auth/password/reset", async ({ request }) => {
    const body = (await request.json()) as { code: string };
    if (body.code !== DEMO_CODE) return new HttpResponse(null, { status: 400 });
    // Reset revokes all sessions → back to sign-in.
    session = false;
    return new HttpResponse(null, { status: 204 });
  }),
  http.post("/v1/auth/logout", () => {
    session = false;
    return new HttpResponse(null, { status: 204 });
  }),
  // Dev-only OIDC shortcut used by the SPA when MSW is on (a real OIDC start is
  // a full-page navigation the worker can't intercept).
  http.post("/v1/auth/oidc/:provider/demo", () => {
    session = true;
    return new HttpResponse(null, { status: 204 });
  }),
  http.post("/v1/verification-codes", async ({ request }) => {
    const body = (await request.json()) as VerificationCodeRequest;
    if (!body.email) return new HttpResponse(null, { status: 400 });
    // Dev/no-op email path returns the code so the confirm screen can hint it.
    return HttpResponse.json({ code: DEMO_CODE });
  }),

  // ── Identity bootstrap ──────────────────────────────────────────────────────
  http.get("/v1/me", async () => {
    const { data } = getScenario();
    if (data === "loading") await delay("infinite");
    if (data === "error") return new HttpResponse(null, { status: 500 });
    return HttpResponse.json(buildMe(sub()));
  }),
  http.get("/v1/me/identities", () => respondData(identities, [])),

  // ── Networks / daemons ──────────────────────────────────────────────────────
  http.get("/v1/tenants/:id/networks", () =>
    respondData(buildNetworks(), []),
  ),
  http.get("/v1/tenants/:id/daemons", () =>
    respondData(buildDaemons(), []),
  ),

  // ── Plan catalog (public) ───────────────────────────────────────────────────
  http.get("/v1/plans", () => respondData(buildPlans(), [])),

  // ── Billing reads ───────────────────────────────────────────────────────────
  http.get("/v1/tenants/:id/billing/payment-method", () =>
    respondData(buildPaymentMethod(sub()), null),
  ),
  http.get("/v1/tenants/:id/billing/invoices", () =>
    respondData(buildInvoices(sub()), []),
  ),
  http.get("/v1/tenants/:id/billing/subscription", () =>
    respondData(buildBillingSubscription(sub()), buildBillingSubscription(sub())),
  ),

  // ── Billing actions (hosted Checkout / change-plan) ─────────────────────────
  // In production checkout / card-update return a Stripe-hosted URL the browser is
  // redirected to, then Stripe redirects back to a same-origin return URL. There is
  // no hosted page under MSW, so the mock returns the same-origin return URL directly —
  // the redirect mechanism is exercised but the reviewer lands back in the app.
  http.post("/v1/tenants/:id/billing/checkout-session", () =>
    HttpResponse.json<CheckoutSessionResponse>({
      url: `${globalThis.location.origin}/subscription?billing=checkout`,
    }),
  ),
  http.post("/v1/tenants/:id/billing/card-update", () =>
    HttpResponse.json<CheckoutSessionResponse>({
      url: `${globalThis.location.origin}/subscription?billing=card-update`,
    }),
  ),
  // Change-plan returns the effect; level vs the current plan (Pro, level 2) decides
  // upgrade / downgrade-scheduled / downgrade-canceled.
  http.post("/v1/tenants/:id/billing/change-plan", async ({ request }) => {
    const body = (await request.json()) as ChangePlanRequest;
    const target = buildPlans().find((p) => p.price_id === body.price_id);
    const current = buildPlans().find((p) => p.price_id === PRICE_PRO);
    if (!target || !current) return new HttpResponse(null, { status: 400 });
    if (target.level === current.level) {
      return HttpResponse.json<ChangePlanResponse>({
        effect: "downgrade_canceled",
        effective_at: null,
        current_price_id: current.price_id,
      });
    }
    if (target.level > current.level) {
      return HttpResponse.json<ChangePlanResponse>({
        effect: "upgraded",
        effective_at: null,
        current_price_id: target.price_id,
      });
    }
    return HttpResponse.json<ChangePlanResponse>(
      {
        effect: "downgrade_scheduled",
        effective_at: new Date(Date.now() + 20 * 86_400_000).toISOString(),
        current_price_id: current.price_id,
      },
      { status: 202 },
    );
  }),

  // ── Subscription lifecycle ──────────────────────────────────────────────────
  http.patch("/v1/tenants/:id", () => new HttpResponse(null, { status: 204 })),
  http.delete("/v1/tenants/:id", () => new HttpResponse(null, { status: 202 })),

  // ── Security actions ────────────────────────────────────────────────────────
  http.delete("/v1/me/identities/:provider", ({ params }) => {
    const provider = params.provider as string;
    if (!identities.some((i) => i.provider === provider)) {
      return new HttpResponse(null, { status: 404 });
    }
    // At least one sign-in method must remain (mirrors the backend guard).
    if (identities.length <= 1) {
      return HttpResponse.json(
        { error: "At least one sign-in method must stay connected." },
        { status: 409 },
      );
    }
    identities = identities.filter((i) => i.provider !== provider);
    return new HttpResponse(null, { status: 204 });
  }),
  // Authenticated set/change password: a valid code sets the password identity and
  // (server-side) rotates the session — here we just stay "logged in" and reflect the
  // new password method so the Security card flips to "Change password".
  http.post("/v1/me/password", async ({ request }) => {
    const body = (await request.json()) as { code: string };
    if (body.code !== DEMO_CODE) return new HttpResponse(null, { status: 401 });
    if (!identities.some((i) => i.provider === "password")) {
      identities = [
        ...identities,
        {
          provider: "password",
          label: "pedro@example.com",
          connected_at: new Date().toISOString(),
        },
      ];
    }
    return new HttpResponse(null, { status: 204 });
  }),
  http.delete("/v1/me/sessions", () => {
    session = false;
    return new HttpResponse(null, { status: 204 });
  }),
];
