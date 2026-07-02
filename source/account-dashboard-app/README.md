# @wardnet/account-dashboard-app — My Account SPA

The web app where Wardnet Cloud customers sign in, manage their profile, and
manage their subscription. **Vite + React 19 + TypeScript + react-router**,
composing **`@wardnet/ui`** from the design system, built **MSW-first** so it is
fully developable with zero backend, then pointed at the real `/v1` API via a
Vite dev proxy.

This is PR4 of the My Account initiative (issue #19). The design reference lives
in [`design/`](./design).

## Quick start

```sh
# One-time: allow installing @wardnet/* from GitHub Packages (for the published
# build; the dev flow below uses a local link and doesn't need this).
gh auth refresh -s read:packages
export NODE_AUTH_TOKEN="$(gh auth token)"

corepack enable
yarn install
yarn dev            # MSW-mocked, no backend needed
```

Open the app, then use the dev-only **Demo** switcher in the top bar to drive the
mock state: subscription (`trial · active · grace · cancelled`) × data
(`ready · loading · error · empty`). Demo confirm code: **`424242`**.

## Scripts

| Script | What it does |
|---|---|
| `yarn dev` | Vite dev server (MSW on by default in dev). |
| `yarn build` | `tsc -b` type-check + production bundle. |
| `yarn type-check` | Type-check only. |
| `yarn test` | Vitest + Testing Library + MSW (integration tests). |
| `yarn preview` | Serve the production build locally. |

## Architecture

- **Routing** — auth (unauthenticated): `/signin /register /forgot /confirm
  /set-password`; account (app shell): `/overview /subscription /security`.
- **Auth** (`src/auth`) — on load, a silent `POST /v1/auth/token` exchanges the
  httpOnly session cookie for a 5-min USER JWT held **in memory**; it is attached
  as `Authorization: Bearer` to USER calls. `401` → logged out → `/signin`.
- **Subscription spine** (`src/account/spine.ts`) — the single derivation that
  maps subscription status → every pill / CTA / banner / blocked action and the
  entitlement usage tones. `trialing→Trial`, `active→Active`, `past_due→Grace`,
  `canceled→Cancelled`.
- **Data** (`src/api`) — TanStack Query hooks per `/v1` endpoint; a shared
  `QueryStates` wrapper renders skeleton / error+Retry / empty / ready.
- **MSW** (`src/mocks`) — handlers for the full contract, driven by the Demo
  scenario store. Reused by the Vitest suite.

## Config flags

- `VITE_ENABLE_MSW` (default on in dev) — set `false` to hit the real `/v1` via
  the dev proxy instead of the mock layer.
- `VITE_ENABLE_DEMO` (default on in dev) — the Demo switcher. **Stripped from
  production builds** (along with MSW) via dead-code elimination.
- `VITE_API_PROXY` (default `http://localhost:8080`) — the backend the dev proxy
  targets when MSW is off.

## Running against a real backend

The session cookie is httpOnly, so the SPA and API must be **same-origin**. The
Vite dev server proxies `/v1` → the backend (mirroring nginx in prod):

```sh
# run a local wardnet-cloud backend on :8080, then:
VITE_ENABLE_MSW=false VITE_API_PROXY=http://localhost:8080 yarn dev
```

Cookies set by the backend on `/v1/auth/*` flow through the proxy, so the silent
JWT exchange and login work end-to-end.

## Design-system consumption (dev vs published)

During co-development the `@wardnet/{ui,styles}` dependencies use a **`link:`** to
the sibling `wardnet-design-system` checkout (build it with `yarn build` there;
the new components — `CodeInput`, `Divider`, `Meter`, `OAuthButton`,
`ThemeToggle`, `TextLink` — ship in that PR).

**At tie-up**, flip those dependencies to the published **`@wardnet/ui@^0.2.0`**
range (and `@wardnet/styles`), so CI installs from GitHub Packages with the
built-in `GITHUB_TOKEN` (`packages: read`). The DS PR must merge + publish first.
