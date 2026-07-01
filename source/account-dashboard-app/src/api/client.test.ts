import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";
import { server } from "../mocks/server";
import {
  apiFetch,
  setTokenRefresher,
  setUnauthorizedHandler,
  tokenStore,
} from "./client";

afterEach(() => {
  tokenStore.set(null);
  setTokenRefresher(null);
  setUnauthorizedHandler(null);
});

/** A protected probe that rejects a stale token and accepts the freshly-minted one. */
function probeAcceptingFreshToken() {
  server.use(
    http.get("/v1/probe", ({ request }) =>
      request.headers.get("Authorization") === "Bearer fresh"
        ? HttpResponse.json({ ok: true })
        : new HttpResponse(null, { status: 401 }),
    ),
  );
}

describe("apiFetch 401 re-exchange", () => {
  it("silently re-exchanges and retries once when the JWT expired mid-session", async () => {
    probeAcceptingFreshToken();
    tokenStore.set("stale");
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    const refresh = vi.fn(async () => {
      tokenStore.set("fresh");
      return true;
    });
    setTokenRefresher(refresh);

    // The first call 401s on the stale token, re-exchanges, and the retry succeeds —
    // the user is never dropped to logged-out.
    await expect(apiFetch("/probe")).resolves.toEqual({ ok: true });
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("drops to logged-out only when the re-exchange itself fails", async () => {
    server.use(
      http.get("/v1/probe", () => new HttpResponse(null, { status: 401 })),
    );
    tokenStore.set("stale");
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    setTokenRefresher(async () => false);

    await expect(apiFetch("/probe")).rejects.toMatchObject({ status: 401 });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it("coalesces concurrent 401s onto a single re-exchange", async () => {
    probeAcceptingFreshToken();
    tokenStore.set("stale");
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    setTokenRefresher(async () => {
      calls += 1;
      await gate; // hold all concurrent 401s in the same in-flight window
      tokenStore.set("fresh");
      return true;
    });

    const inflight = Promise.all([
      apiFetch("/probe"),
      apiFetch("/probe"),
      apiFetch("/probe"),
    ]);
    // Let all three requests 401 and enter the coalesced refresh before it resolves.
    await new Promise((r) => setTimeout(r, 20));
    release();
    await expect(inflight).resolves.toEqual([{ ok: true }, { ok: true }, { ok: true }]);
    expect(calls).toBe(1);
  });
});
