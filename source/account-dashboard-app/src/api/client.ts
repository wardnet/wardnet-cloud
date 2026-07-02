import { toast } from "@wardnet/ui";
import { API_BASE } from "../config/env";

/** Error carrying the HTTP status so callers can branch on 401 etc. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * Thrown by checkout / change-plan when a promo that was displayed has lapsed by the
 * time it is applied (backend `409 promo_unavailable`). Carries the real price so the
 * UI can re-confirm at full price (see ADR-0011).
 */
export class PromoUnavailableError extends Error {
  constructor(
    public readonly actualAmountCents: number,
    public readonly currency: string,
  ) {
    super("promo_unavailable");
    this.name = "PromoUnavailableError";
  }
}

// The 5-min USER JWT lives only in memory (never localStorage) — see ADR-0009.
let accessToken: string | null = null;
let onUnauthorized: (() => void) | null = null;
let onTokenRefresh: (() => Promise<boolean>) | null = null;
let refreshInFlight: Promise<boolean> | null = null;

export const tokenStore = {
  get: () => accessToken,
  set: (token: string | null) => {
    accessToken = token;
  },
};

/** Register a handler invoked when re-auth is impossible (drops to logged-out). */
export function setUnauthorizedHandler(handler: (() => void) | null) {
  onUnauthorized = handler;
}

/**
 * Register the silent token re-exchange (session cookie → fresh JWT). Returns `true`
 * when a new token was minted. A short-lived USER JWT expiring mid-session must not
 * log the user out — the next call re-exchanges and retries (see ADR-0009).
 */
export function setTokenRefresher(fn: (() => Promise<boolean>) | null) {
  onTokenRefresh = fn;
}

/** Coalesce concurrent 401s onto a single in-flight re-exchange. */
function refreshToken(): Promise<boolean> {
  if (!onTokenRefresh) return Promise.resolve(false);
  refreshInFlight ??= onTokenRefresh().finally(() => {
    refreshInFlight = null;
  });
  return refreshInFlight;
}

type FetchOptions = RequestInit & {
  /** Skip attaching the bearer token (for the silent-exchange call itself). */
  anonymous?: boolean;
};

/**
 * Same-origin `/v1` fetch. Attaches the in-memory USER JWT as a Bearer token,
 * always sends the session cookie (`credentials: include`), and raises
 * `ApiError` on non-2xx — invoking the unauthorized handler on 401.
 */
export async function apiFetch<T>(
  path: string,
  opts: FetchOptions = {},
): Promise<T> {
  return requestWithRetry<T>(path, opts, false);
}

async function requestWithRetry<T>(
  path: string,
  opts: FetchOptions,
  isRetry: boolean,
): Promise<T> {
  const { anonymous, headers, ...init } = opts;
  const finalHeaders = new Headers(headers);
  if (!anonymous && accessToken) {
    finalHeaders.set("Authorization", `Bearer ${accessToken}`);
  }
  if (init.body && !finalHeaders.has("Content-Type")) {
    finalHeaders.set("Content-Type", "application/json");
  }

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: finalHeaders,
      credentials: "include",
    });
  } catch {
    // Network-level failure (offline, DNS, connection reset) — no HTTP response.
    toast.error("Network error — check your connection and try again.");
    throw new ApiError(0, "Network error");
  }

  if (res.status === 401) {
    // A short-lived USER JWT expiring mid-session should silently re-exchange (via the
    // session cookie) and retry once — not drop the user to the login screen. Only give
    // up if the exchange fails or the retried call still 401s.
    if (!anonymous && !isRetry && (await refreshToken())) {
      return requestWithRetry<T>(path, opts, true);
    }
    if (!anonymous) onUnauthorized?.();
    throw new ApiError(401, "Unauthorized");
  }
  if (!res.ok) {
    // Surface unexpected server faults once, centrally, for every call. Client
    // errors (4xx) are expected and handled at the call site (inline validation
    // messages); 401 is handled above (re-auth), so neither toasts here.
    if (res.status >= 500) {
      toast.error("Something went wrong. Please try again.");
    } else if (res.status === 409) {
      // A lapsed-promo signal carries the real price for the re-confirm prompt.
      const body = (await res.json().catch(() => null)) as {
        error?: string;
        actual_amount_cents?: number;
        currency?: string;
      } | null;
      if (body?.error === "promo_unavailable") {
        throw new PromoUnavailableError(
          body.actual_amount_cents ?? 0,
          body.currency ?? "usd",
        );
      }
    }
    throw new ApiError(res.status, `Request failed: ${res.status}`);
  }
  if (res.status === 204) return undefined as T;

  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}
