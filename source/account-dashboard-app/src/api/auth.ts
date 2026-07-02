import { apiFetch } from "./client";
import type {
  PasswordLoginRequest,
  PasswordResetRequest,
  PasswordSignupRequest,
  SetPasswordRequest,
  TokenResponse,
  VerificationCodeRequest,
  VerificationCodeResponse,
} from "./contract";

/**
 * Silent session→JWT exchange. Reads the httpOnly session cookie server-side
 * and mints a 5-min USER JWT. `anonymous` so a 401 here just means "logged out"
 * rather than triggering the global unauthorized handler.
 */
export function exchangeToken(): Promise<TokenResponse> {
  return apiFetch<TokenResponse>("/auth/token", {
    method: "POST",
    anonymous: true,
  });
}

export function passwordLogin(body: PasswordLoginRequest): Promise<void> {
  return apiFetch<void>("/auth/password/login", {
    method: "POST",
    anonymous: true,
    body: JSON.stringify(body),
  });
}

export function passwordSignup(body: PasswordSignupRequest): Promise<void> {
  return apiFetch<void>("/auth/password/signup", {
    method: "POST",
    anonymous: true,
    body: JSON.stringify(body),
  });
}

export function passwordReset(body: PasswordResetRequest): Promise<void> {
  return apiFetch<void>("/auth/password/reset", {
    method: "POST",
    anonymous: true,
    body: JSON.stringify(body),
  });
}

/** Authenticated set/change password (`POST /v1/me/password`). Uses the in-memory
 *  USER JWT (not anonymous); the server revokes all sessions and sets a fresh
 *  session cookie, so the caller stays signed in. */
export function setPassword(body: SetPasswordRequest): Promise<void> {
  return apiFetch<void>("/me/password", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function requestVerificationCode(
  body: VerificationCodeRequest,
): Promise<VerificationCodeResponse> {
  return apiFetch<VerificationCodeResponse>("/verification-codes", {
    method: "POST",
    anonymous: true,
    body: JSON.stringify(body),
  });
}

export function logout(): Promise<void> {
  return apiFetch<void>("/auth/logout", { method: "POST" });
}

/** OIDC start is a full-page navigation (optionally in link mode). */
export function oidcStartUrl(
  provider: "google" | "github",
  mode?: "link",
): string {
  const q = mode ? `?mode=${mode}` : "";
  return `/v1/auth/oidc/${provider}/start${q}`;
}
