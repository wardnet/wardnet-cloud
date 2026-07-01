import { describe, expect, it } from "vitest";
import { computeUsage, deriveAccountState } from "./spine";
import { buildMe } from "../mocks/db";

describe("deriveAccountState", () => {
  it("maps each subscription status to its lifecycle + presentation", () => {
    expect(deriveAccountState(buildMe("trial")).lifecycle).toBe("trial");
    expect(deriveAccountState(buildMe("active")).lifecycle).toBe("active");
    expect(deriveAccountState(buildMe("grace")).lifecycle).toBe("grace");
    expect(deriveAccountState(buildMe("cancelled")).lifecycle).toBe("cancelled");

    const grace = deriveAccountState(buildMe("grace"));
    expect(grace.statusLabel).toBe("Grace");
    expect(grace.pillVariant).toBe("warn");
    expect(grace.isActive).toBe(false);
    expect(grace.isPremiumPaused).toBe(true);
  });

  it("treats a null subscription as cancelled with free entitlement", () => {
    const state = deriveAccountState({
      tenant_id: "t",
      email: "x@y.z",
      subscription: null,
    });
    expect(state.lifecycle).toBe("cancelled");
    expect(state.entitlement).toEqual({ max_networks: 1, max_daemons: 1 });
  });

  it("keeps premium active for trial and active", () => {
    expect(deriveAccountState(buildMe("trial")).isActive).toBe(true);
    expect(deriveAccountState(buildMe("active")).isActive).toBe(true);
  });
});

describe("computeUsage", () => {
  it("flags accent / warn / danger tones by remaining slots", () => {
    expect(computeUsage(2, 3).tone).toBe("accent");
    expect(computeUsage(24, 25).tone).toBe("warn");
    expect(computeUsage(25, 25).tone).toBe("danger");
  });

  it("marks near-limit at one-or-fewer remaining", () => {
    expect(computeUsage(2, 3).nearLimit).toBe(false);
    expect(computeUsage(24, 25).nearLimit).toBe(true);
    expect(computeUsage(25, 25).nearLimit).toBe(true);
  });

  it("computes a clamped percentage", () => {
    expect(computeUsage(2, 4).pct).toBe(50);
    expect(computeUsage(30, 25).pct).toBe(100);
    expect(computeUsage(0, 0).pct).toBe(0);
  });
});
