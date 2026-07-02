# dev-stack — run the My Account SPA against the real backend

This stack runs the real **`tenants`** service (the public API for the My Account
SPA) locally so you can exercise the genuine flows — password + **Google/GitHub
OIDC** sign-in, **emailed verification codes** (Resend), and the **Stripe** paid
lifecycle — instead of the MSW mock layer.

```
browser ──▶ Vite dev (:5173, proxies /v1) ──▶ nginx (:8080, L4 stream,
            prepends PROXY-protocol v1) ──▶ tenants API (:80) ──▶ Postgres
```

The nginx hop exists only to add the PROXY-protocol v1 header the API listener
requires (it drops any connection without one). Everything is **same-origin
through the Vite dev server on :5173**, which is why `http://localhost:5173`
works as the OAuth redirect base with no tunneling.

> Mock vs real: `yarn dev` alone still uses MSW. This stack is for when you want
> the real backend. The two are mutually exclusive per browser tab.

---

## One-time setup (the bits only you can do)

Copy the env template and fill it in:

```sh
cp dev-stack/.env.example dev-stack/.env
```

Then complete the external accounts below and paste the values into `dev-stack/.env`.

### 1. Google OAuth  (optional — leave blank to disable Google sign-in)
- Google Cloud Console → **APIs & Services → Credentials → Create OAuth client ID**
  → application type **Web application**.
- **Authorized redirect URI** (exactly): `http://localhost:5173/v1/auth/oidc/google/callback`
- Copy the client ID + secret into `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`.

### 2. GitHub OAuth  (optional — leave blank to disable GitHub sign-in)
- GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**.
- **Authorization callback URL** (exactly): `http://localhost:5173/v1/auth/oidc/github/callback`
- Copy the client ID + secret into `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`.

### 3. Stripe (test mode)
- Stripe Dashboard in **Test mode** → Developers → API keys → copy the **secret
  key** (`sk_test_…`) into `STRIPE_SECRET_KEY`.
- Create a **Product** with a recurring **Price**, and add price **metadata**
  `max_networks` + `max_daemons` (these become the account's entitlement). Keep the
  price id in sync with `account-dashboard-app/src/lib/plan.ts`.
- Webhooks (needed for the subscription to actually flip to active): install the
  [Stripe CLI](https://stripe.com/docs/stripe-cli), then in a separate terminal:
  ```sh
  stripe listen --forward-to localhost:5173/v1/billing/stripe/webhook
  ```
  Paste the printed `whsec_…` into `STRIPE_WEBHOOK_SECRET`. Keep this running while
  you test. Use test card `4242 4242 4242 4242`, any future expiry / CVC.

### 4. Email codes (Resend) — optional
- Set `RESEND_API_KEY` (+ a verified `EMAIL_FROM`) to **actually email** the
  6-digit codes. Resend's `onboarding@resend.dev` only delivers to your own
  account email; verify a domain to send anywhere.
- Leave `RESEND_API_KEY` blank to skip email — the backend then **returns the code
  in the API response** and the Confirm screen shows it (handy for fast testing).

---

## Run it

From `source/`:

```sh
make dev           # one-shot: backend up (detached) + SPA in the foreground
```

…or drive the pieces separately:

```sh
make dev-up        # generates certs, builds + starts postgres + tenants + nginx
make dev-logs      # tail the tenants logs (codes are logged here if email is off)
make dev-app       # run the SPA against the real backend (MSW off); Ctrl-C to stop
```

Open http://localhost:5173. Tear down with `make dev-down` (drops the DB volume).

> The `make dev-*` targets auto-detect the container engine: if no Docker daemon
> is reachable they fall back to the Podman machine socket, so you don't need to
> export `DOCKER_HOST`.

The Postgres schema is migrated automatically by `tenants` on boot, so the first
sign-up creates your tenant from scratch.

### Overriding the proxy target
The SPA's Vite proxy targets `http://localhost:8080` by default (the nginx
sidecar). Override with `VITE_API_PROXY=… yarn dev` if you remap the port.

---

## Troubleshooting
- **Sign-in/sign-up hangs or 502** — the API only accepts connections via the
  nginx PROXY sidecar; make sure you're hitting `:8080` (the Vite proxy default),
  not the container's `:80` directly.
- **Every request suddenly returns empty/500 with nothing in the tenants logs,
  right after a backend restart** — the nginx stream proxy cached the old `tenants`
  container IP, so requests never reach the backend. Fix: `make dev-up` (it bounces
  nginx) or `docker-compose -f dev-stack/compose.yaml restart nginx`. Recreating
  `tenants` alone (e.g. to pick up an `.env` change) always needs nginx bounced.
- **OAuth "redirect_uri_mismatch"** — the registered URI must be exactly
  `http://localhost:5173/v1/auth/oidc/{google|github}/callback`.
- **Subscription doesn't activate after checkout** — `stripe listen` isn't running,
  or `STRIPE_WEBHOOK_SECRET` doesn't match the CLI's printed secret.
- **Didn't get the email code** — if `RESEND_API_KEY` is blank the code isn't
  emailed; read it from `make dev-logs` or the Confirm screen. With Resend on,
  the onboarding sender only emails your own Resend account address.
- **certs missing** — `make dev-certs` (run automatically by `make dev-up`).
