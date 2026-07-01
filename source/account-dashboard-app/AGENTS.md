# account-dashboard-app agent guide

The My Account SPA (issue #19 / PR4). Vite + React 19 + TypeScript +
react-router, composing `@wardnet/ui`, built MSW-first. Read `README.md` for the
dev/run flow; this file is the conventions + invariants for changing the code.

## Layout

```
src/
  api/         contract types (mirror wardnet_common::contract), fetch client, TanStack Query hooks
  account/     spine.ts — subscription-status → presentation derivation (the "spine")
  auth/        AuthProvider — silent JWT exchange, in-memory token, 401 handling
  components/  feedback.tsx — Skeleton / ErrorCard / EmptyState / QueryStates
  config/      env.ts — MSW_ENABLED / DEMO_ENABLED / API_BASE build flags
  lib/         format, validation, network-status, plan constants
  mocks/       MSW: handlers, sample db, scenario store (Demo switcher source)
  routes/      auth/* screens + AuthShell; account/* tabs + AccountLayout/TopBar/DemoSwitcher
  theme/       useTheme + ThemeContext (data-theme on <html>)
  test/        setup.ts (MSW server + jsdom polyfills), utils.tsx (renderApp)
```

## Must-know conventions

1. **Compose `@wardnet/ui`; never re-implement a DS component.** If the design
   needs something the DS lacks, extract it into `@wardnet/ui` (see the PR's DS
   companion), don't hand-roll it here. App-local components are genuine
   compositions of DS primitives (accent-stripe status card, underline TabNav,
   Avatar, billing DataTable).
2. **Typography only via `<Text variant>` / `<Heading level>`** — never a raw
   font-size. Layout glue is plain CSS Modules using DS tokens (`var(--bg)`,
   `var(--line)`, `var(--accent)`, …). No Tailwind, no invented colors/type.
3. **One emerald primary `Button` per view; everything else ghost/ink.**
4. **The subscription status is the spine.** Derive every pill / CTA / banner /
   blocked-or-near-limit action from `deriveAccountState` (`src/account/spine.ts`)
   — do not branch on `status` ad-hoc in a screen. Status map: `trialing→Trial`,
   `active→Active`, `past_due→Grace`, `canceled→Cancelled`.
5. **Wire DTOs, don't redefine them.** Wire types live in `src/api/contract.ts`
   and mirror `source/crates/common/src/contract.rs`. Keep them in lock-step; a
   backend contract change should change this file too.
6. **Auth token is in memory only** (`src/api/client.ts` `tokenStore`) — never
   `localStorage`. "Am I logged in?" is answered by attempting the silent
   `POST /v1/auth/token` exchange, not by reading the (httpOnly) cookie.
7. **No in-app card capture.** Add/renew/reactivate → hosted Checkout redirect;
   update/manage → hosted Portal redirect (PCI SAQ-A). Cancel → `AlertModal` →
   `PATCH /v1/tenants/{id} {subscription_status:"canceled"}`.
8. **No "Degraded"/health signal.** Network pills derive only from
   `provisioning_state` (`src/lib/network.ts`): `active→Online`,
   `provisioning→Provisioning`, `deprovisioning→Deprovisioning`.
9. **Demo switcher + MSW are dev-only and must stay strippable.** Gate them on
   `DEMO_ENABLED` / `MSW_ENABLED` (which fold to `false` under
   `import.meta.env.PROD`) so dead-code elimination removes them from production
   bundles. Don't import `src/mocks/*` from non-dev code paths.

## Tests

Vitest + Testing Library + MSW. `src/test/utils.tsx` `renderApp(route)` mounts the
full provider stack on a `MemoryRouter`. Set the scenario with
`setScenario(...)` and authenticate with `setMockSession(true)` before rendering
the account area. Cover the Demo matrix (subscription × data states) for new
screens. Run `yarn test`; all of `yarn type-check` + `yarn test` + `yarn build`
must be green.

## Gotchas

- The linked DS ships its own React copy; `vite.config.ts` aliases
  `react`/`react-dom`/`lucide-react`/`radix-ui`/`cmdk` to the app's copies to
  avoid dueling-React. Keep that alias when adding DS-backed deps.
- `data-theme` is set on `<html>` so Radix portals (modals, menus) inherit the
  theme. Don't scope the theme lower.
