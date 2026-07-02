// Build/runtime flags. `import.meta.env.PROD` strips the dev-only affordances
// (MSW + the Demo switcher) from production bundles via dead-code elimination.

/** Use the in-browser MSW mock layer instead of the real `/v1` dev proxy. */
export const MSW_ENABLED =
  import.meta.env.DEV && import.meta.env.VITE_ENABLE_MSW !== "false";

/** Expose the dev-only Demo state switcher (reviewer affordance). */
export const DEMO_ENABLED =
  import.meta.env.DEV && import.meta.env.VITE_ENABLE_DEMO !== "false";

/** All API calls are same-origin under `/v1` (MSW intercepts, or Vite proxies). */
export const API_BASE = "/v1";
