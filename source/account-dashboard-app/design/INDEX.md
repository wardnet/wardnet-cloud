# My Account — design handoff

Reference design for the **My Account** SPA (`source/account-dashboard-app`).

- `Wardnet - My Account.dc.html` — high-fidelity HTML prototype of the full app
  (auth flows + Overview / Subscription / Security). Rendered from one
  `React.createElement` class against a pre-bundled `@wardnet/ui`. Open in a
  browser to preview. **Recreate it for real** with the project's framework,
  routing, and data layer — compose the published `@wardnet/ui` components, do
  not re-implement them.
- `README.md` — the design spec (tokens, components, data model, screen-by-screen
  behaviour).

These are a **reference**, not production code to copy line-for-line. Where the
prototype diverges from the real backend (in-app card modal, invoice table,
Security-tab actions), follow the API contract in the SPA tracking issue, which
records the agreed reconciliation (hosted Stripe Checkout/Portal, provider-proxied
billing reads, email-code-exchange change-password, etc.).
