// Demo state the MSW handlers read, driven by the dev-only Demo switcher.
// Persisted to localStorage so a reload keeps the selected scenario.

export type SubScenario = "trial" | "active" | "grace" | "cancelled";
export type DataScenario = "ready" | "loading" | "error" | "empty";

export interface Scenario {
  subscription: SubScenario;
  data: DataScenario;
}

const STORAGE_KEY = "wardnet-demo-scenario";

const DEFAULT: Scenario = { subscription: "trial", data: "ready" };

function load(): Scenario {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT;
    return { ...DEFAULT, ...(JSON.parse(raw) as Partial<Scenario>) };
  } catch {
    return DEFAULT;
  }
}

let current: Scenario = load();
const listeners = new Set<(s: Scenario) => void>();

export const getScenario = (): Scenario => current;

export function setScenario(patch: Partial<Scenario>) {
  current = { ...current, ...patch };
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(current));
  } catch {
    // ignore storage failures (private mode etc.)
  }
  for (const l of listeners) l(current);
}

export function subscribeScenario(listener: (s: Scenario) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
