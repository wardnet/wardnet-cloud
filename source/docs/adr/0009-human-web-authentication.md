# 9. Human/web authentication: cookie session → minted JWT, federated identities

Date: 2026-06-19
Status: Accepted

## Context

The account plane (`/v1/tenants/*`, `authenticate(USER)`) was built in earlier slices but had
**no front door**: nothing minted a `USER` token, so it was reachable only by test-minted JWTs.
A human's only identity was the `tenants.email` column — no credential store, no login. Worse,
`POST /v1/tenants` (create account) sat *inside* the `USER`-auth group, a chicken-and-egg: you
needed a user token to create the account that would grant you one.

WS-F adds the human front door. The product requirement: a SPA login form supporting
**email+password** *and* **federated login (Google, GitHub, and others alike)**, where the SPA
must both guard its own routes and call our APIs. The daemon credential model
(key-PoP → mint JWT, ADR-0002) does not fit a browser; OAuth forces a redirect round-trip; and
the existing API authenticates only `Authorization: Bearer <JWT>` (invariant #18).

## Decision

### Aggregate segregation — the Identities aggregate (`IdentitiesService`)

The login methods + sessions are **their own aggregate**, owned by a new
**`IdentitiesService`** — *not* folded into `TenantsService` (invariant #23, ADR-0007).
It holds **only** its own two repositories (`tenant_identities`, `sessions`), plus the
password hasher, the federated providers, and a shared `Arc<Signer>` (the signing key
is a capability, like the event bus — not aggregate state). It coordinates with the
tenant aggregate through the same one-way-edge + domain-event pattern the subscription
aggregate uses:

- **Reads / create-delegation** are direct method calls on the owner — a one-way
  `IdentitiesService → TenantsService` edge (mirroring `TenantsService →
  SubscriptionService::current`): `find_tenant_by_email` (the join-key read),
  `register_tenant` (web-first signup — the write *and* `TenantCreated` stay in the
  tenant aggregate), and `consume_signup_code` (the email-proving gate-1 primitive,
  keeping `enrollment_codes` inside the tenant aggregate). `IdentitiesService` never
  touches the tenant/network/daemon/subscription repositories.
- **The reverse side-effect** rides a domain event: an **identities reactor**
  subscribes to `TenantDeregistered` (already published on deregister) and calls
  `IdentitiesService::purge_for` (delete the tenant's sessions + login methods —
  force-logout). The FK `ON DELETE CASCADE` covers the eventual hard sweep, so a
  dropped event is harmless; the reaction is idempotent.

The edge stays one-way (reads/create forward; the deregister side-effect as an event),
so there is no cycle — the same shape as the subscription/network reactors.

### Identity model — 1:1 user==tenant, verified-email join key

A `USER` principal **is** the tenant (1:1); `sub = tenant_id`. Multi-user teams are explicitly
deferred (a forward-compatible change: introduce a users table later and migrate `sub`, a
TTL-bounded claim change, not a data migration).

Every login method resolves to a tenant by a **provider-verified email** — the one thing
password, Google, and GitHub all share, and the key the `tenants.email` partial-unique index
already enforces. Two **sequential gates**:

1. **`email_verified` — may we trust this email at all?** A provider may *assert* an email
   without proving control of the inbox. If the provider does not mark it verified, reject
   (never reach gate 2). Password login has no provider to assert this, so it manufactures the
   gate itself: a one-time email code (below).
2. **match — returning user or new?** A trusted email matching a live tenant → **auto-link**
   (the email was verified and the tenant was itself born by proving that same email, so no
   separate claim step). No match → **create the tenant** (web-first signup). This is what
   finally makes account creation reachable from the web.

Consequently **tenant creation only ever happens at a credential-proving moment** — the OAuth
callback, password-signup-after-code, or daemon enroll — *never* under `USER` auth.
`register_tenant` (`POST /v1/tenants`) is **deleted**.

### Credential store — one uniform `tenant_identities` table

Login methods are rows: `(tenant_id, provider, subject, secret_hash NULL, email, created_at)`,
unique on `(provider, subject)`.

- Password row: `provider='password'`, `subject=email`, `secret_hash=argon2id(pw)`.
- OIDC row: `provider='google'|'github'`, `subject=<provider subject>`, `secret_hash=NULL`.

Auto-link and "connect another provider" are a single insert; "what can this account log in
with?" is one select. `tenants` stays identity-only (the glossary invariant holds). The
password hash is never logged or echoed (extends invariant #1 to passwords).

### Session model — cookie anchor, short-TTL JWT minted from it

The browser-durable credential is a **server-side `sessions` row** behind an httpOnly+Secure+
SameSite cookie (30-day sliding). The SPA never sees it. For API calls the SPA hits a
`POST /v1/auth/token` **exchange** endpoint that reads the cookie and mints a **short-TTL
(5 min) `USER` JWT** (`aud:[tenants]`, ADR-0008), held only in memory and sent as
`Authorization: Bearer`. Mirrors the daemon model — *daemon: key-PoP → mint JWT; web: cookie →
mint JWT* — so both planes converge on one offline-verified bearer token and the auth layer
never learns about cookies (invariant #18 intact). "Am I logged in?" is answered by *attempting
the mint*, not by reading the (unreadable) cookie.

### Federated flow — backend-orchestrated, two protocols behind one trait

`GET /v1/auth/oidc/{provider}/start` generates `state` + PKCE, stores them in a **signed
httpOnly cookie** (no DB row to reap), and 302s to the provider. `…/callback` validates `state`,
exchanges the code, applies the two gates, ensures the `tenant_identities` row, creates the
session, sets the cookie, and 302s to the SPA. Providers differ by protocol —
**Google is full OIDC** (discovery + `id_token` + JWKS), **GitHub is plain OAuth2** (no
`id_token`; call the user/emails API) — so both sit behind an `ExternalIdentityProvider` trait
(`authorize_url(state, pkce)` + `exchange(code) -> VerifiedIdentity{provider, subject, email,
email_verified}`): a generic-OIDC impl (Google + discovery-based others) and a GitHub adapter.

Password flows reuse the one-time-code primitive: signup (code = gate 1) and reset (code → new
hash, which also deletes the tenant's sessions). Login shares the OAuth callback's
session-creation tail. Provider `client_id`/`client_secret` arrive via `SecretsProvider`/env and
are redacted in `Config` `Debug` (invariant #24 pattern).

## Consequences

- The account plane is reachable; the `register_tenant` chicken-and-egg is gone; invariants
  **#2/#18** are rewritten (USER is no longer "any valid token," and account creation is a
  bootstrap act).
- **Revocation is the primary hijack defence, not TTL.** XSS or cookie theft lets an attacker
  re-mint via the cookie regardless of JWT TTL; what bounds them is deleting the `sessions` row
  (+ httpOnly keeping the cookie unreadable, + TLS). The 5-min JWT TTL narrowly bounds a token
  *leaked without the cookie* (logs, referrer, paste). 5 min is chosen over 2–3 min for margin
  against the verifier's `leeway = 0` clock-skew (ADR-0002).
- New persistent state in the global Tenants DB: `tenant_identities` and `sessions` (both
  FK-cascade from `tenants`, so the existing tombstone sweep reaps them). New deps:
  `argon2`, `axum-extra` (cookies), `openidconnect`, `time` (cookie Max-Age).
- A second aggregate now lives in the `tenants` crate (`IdentitiesService`, alongside
  `SubscriptionService`); the auth surface is `api/auth.rs` (a bootstrap group) plus `GET
  /v1/me` (USER). The USER JWT carries `aud:[tenants]` (ADR-0008) and `sub = tenant_id`.
- **Deferred:** multi-user teams, settings-page connect/disconnect of providers. Both are
  additive on this model (new rows / a `sub` migration), no redesign.
- **Rejected alternatives:** distinct `users` entity from day one (drags in membership/roles/
  invites nothing else anticipated); SPA-held refresh+access tokens (XSS-exfiltratable, messy
  OAuth hand-back); cookie authenticating the API directly (forks the auth layer with a second
  USER transport + CSRF + per-call session lookup, losing offline verify).
