# wardnet-cloud — domain glossary

The shared vocabulary for the cloud platform. Definitions only — no implementation
details. (See `docs/adr/` for the decisions behind these.)

## Identity & accounts

- **Tenant** — an account: just an identity (an email). The root of ownership; its
  billing/entitlement state lives on its [subscription](#subscription), not on the
  tenant row. Lives in the global Tenants DB.
- **User** — the human owner of a [tenant](#tenant), **1:1** with it (`sub = tenant_id`;
  no separate user entity — teams are deferred). Authenticates to the web/account plane
  by a [login method](#login-method); the daemon plane never carries a user. See
  `docs/adr/0009`.
- **Identities aggregate** — the human/web login aggregate, owned by
  `IdentitiesService` (in the `tenants` crate, alongside [Subscription](#subscription)).
  Holds **only** the [login method](#login-method) + [session](#session) repositories;
  it reads/creates tenants via `TenantsService` method calls (a one-way edge) and reacts
  to `TenantDeregistered` by purging a tenant's sessions + login methods. Never touches
  the tenant/network/daemon/subscription repositories. See `docs/adr/0009`.
- **Login method / identity** — one way an account can authenticate: a `password` (an
  argon2id hash) or a linked external provider (`google`, `github`, …). An account may
  hold several, all resolving to the one tenant via [verified email](#verified-email-join-key).
  Stored as rows in `tenant_identities`, owned by the [Identities aggregate](#identities-aggregate);
  `tenants` stays identity-only.
- **Session** — the browser-durable, **revocable** web credential: a server-side row
  (`sessions`, owned by the [Identities aggregate](#identities-aggregate)) behind an
  httpOnly cookie (30-day sliding), created at login. Distinct from the short-lived
  [JWT](#caller-type) it mints via the silent exchange — the session is what logout /
  password-reset / deregister destroys. See `docs/adr/0009`.
- **Subscription** — the billing aggregate that **grants** a tenant's
  [entitlement](#entitlement). A tenant has a 1:N history with at most one **live**
  (non-canceled) row — its *current* subscription. Status is `trialing → active →
  past_due → canceled` (Stripe-driven once paid). The free [trial](#trial) is itself
  a subscription row. Owned by `SubscriptionService`; no other service touches it.
- **Plan** — a purchasable tier, defined as a Stripe Price whose metadata carries the
  `max_networks` / `max_daemons` it grants. Adding a plan is a Stripe change, no deploy.
- **Network** — one wardnet network owned by a tenant. Holds a globally-unique
  **vanity slug** and a [provisioning state](#provisioning-state). The DNS record
  belongs to the network, not to any single device. A tenant may own several.
- **Daemon** — a device bound to a network, holding its own Ed25519 keypair. A
  network may have many daemons (active/active); each authenticates and is issued
  tokens independently.
- **Vanity / slug** — the network's public name (`<slug>.<zone>`); globally unique.
- **Entitlement** — the limits a [subscription](#subscription)'s plan grants: at
  minimum `max_networks` and `max_daemons`. Default for the free trial: 1 / 1.
- **Trial** — the card-less free [subscription](#subscription) a tenant starts with
  (`trialing`, `1/1`, `trial_expires_at = now + TRIAL_DAYS`). Service continues
  through a **grace** window past expiry, after which the reaper cancels it.
- **Grace** — the extra window a `trialing` (post-`trial_expires_at`) or `past_due`
  (post-`current_period_end`) subscription keeps service before the subscription
  reaper cancels it (cascading network deprovisioning). Two configurable windows
  (trial grace, payment grace), both 15 days by default.
- **Checkout session** — the Stripe-hosted page a user is redirected to (from the
  account plane) to subscribe to a plan; on completion the webhook converts the trial
  to a paid subscription.
- **Billing portal** — the Stripe-hosted page where a user manages their payment
  method / subscription; reached via a portal session from the account plane.
- **Deregister** — the account-closing act: the tenant is **tombstoned**, all its
  networks are cascaded to [deprovisioning](#provisioning-state), and its
  subscription is canceled. Idempotent. Distinct from a subscription cancel (which
  is reversible and leaves the account intact). The owning user triggers it
  (`DELETE /v1/tenants/{id}`).
- **Tombstone** — the terminal marker (`deregistered_at`) on a deregistered tenant.
  A tombstoned tenant cannot mint tokens or enroll daemons, and its email is freed
  for a fresh signup immediately (only *live* tenants reserve their email). The row
  itself lingers until the **sweep** removes it.
- **Sweep** — the periodic reaper that deletes tombstoned tenants once their
  networks are fully deprovisioned (the DDNS reaper having torn down DNS first),
  FK-cascading the tenant's subscriptions, daemons, codes, and pending enrollments.
  N-replica-safe and idempotent.
- **Deregister** — the account-closing act: the tenant is **tombstoned**, all its
  networks are cascaded to [deprovisioning](#provisioning-state), and its
  subscription is canceled. Idempotent. Distinct from a subscription cancel (which
  is reversible and leaves the account intact). The owning user triggers it
  (`DELETE /v1/tenants/{id}`).
- **Tombstone** — the terminal marker (`deregistered_at`) on a deregistered tenant.
  A tombstoned tenant cannot mint tokens or enroll daemons, and its email is freed
  for a fresh signup immediately (only *live* tenants reserve their email). The row
  itself lingers until the **sweep** removes it.
- **Sweep** — the periodic reaper that deletes tombstoned tenants once their
  networks are fully deprovisioned (the DDNS reaper having torn down DNS first),
  FK-cascading the tenant's subscriptions, daemons, codes, and pending enrollments.
  N-replica-safe and idempotent.

## Eventing & reconciliation

- **Domain event** — an in-process signal a service raises so another aggregate can
  react, instead of one service reaching into another's repository (`TenantCreated`,
  `TenantDeregistered`, `SubscriptionDeactivated`). Best-effort delivery (a broadcast
  bus); the reconcile is the guarantee. See `docs/adr/0007`.
- **Reactor** — a long-running loop subscribed to the event bus that turns a domain
  event into a call on the **owning** service's method (e.g. `TenantCreated` →
  `SubscriptionService::create_trial`; `SubscriptionDeactivated` →
  `TenantsService::deprovision_networks_for`). Idempotent, so a redelivery is harmless.
- **Reconcile** — the periodic safety net that re-derives desired state for any dropped
  event: it backfills a missing trial and deprovisions an unsubscribed tenant's networks.

## Enrollment credentials

- **One-time code** — a short-lived, single-use, email-proving credential. A
  *new-signup* code (no tenant yet) or an *add-daemon* code (existing tenant).
  Consumed once, at enroll.
- **Pending enrollment** — a TTL'd binding of a daemon's public key to a tenant,
  written at enroll. Lets a not-yet-registered daemon authenticate (mint a
  tenant-scoped token) before it has a network. Self-expires.
- **Enroll** — the act of consuming a code: create/resolve the tenant and write the
  pending binding. Mints no token.

## Auth planes (who may call an endpoint)

- **Caller type** — `SERVICE`, `DAEMON`, or `USER`; an endpoint declares the set it
  accepts. `SERVICE` authenticates by mesh **mTLS**; `DAEMON`/`USER` by **JWT**
  (a daemon additionally proves possession of its key — see PoP).
- **PoP (proof-of-possession)** — a daemon signs each request with its Ed25519 key;
  the signature is checked against the token's `cnf` key. Users are bearer-only.
- **Audience (`aud`)** — the set of services a JWT is valid at, drawn from the mesh
  service namespace (`tenants`/`ddns`/`tunneller`). Each service verifies its own name
  is in `aud`. A user token is `[tenants]`; a daemon token is `[tenants]` before it binds
  a network and `[tenants, ddns, tunneller]` after. See `docs/adr/0008`.
- **Verified-email join key** — the rule that maps any login method to a tenant: a
  *provider-verified* email (gate 1 — password proves it with a one-time code, OIDC with
  `email_verified`) that resolves to at most one live tenant (gate 2 — match → auto-link,
  no match → web-first signup). Tenant creation only ever happens at such a
  credential-proving moment, never under USER auth. See `docs/adr/0009`.
- **Mesh plane** — the private, mTLS-only service-to-service boundary
  (DDNS ↔ Tenants, Tunneller ↔ Tenants, and Tunneller node ↔ node). Not reachable
  by daemons or users.
- **SPIFFE identity** — a mesh service's identity, carried as the **only** SAN (a URI,
  no DNS name) of its mTLS leaf: `spiffe://<trust_domain>/<env>/<scope>/<service>`.
  `scope` is `global` or a region slug; `service` is `tenants` / `ddns` / `tunneller`.
  A service learns its own identity by parsing its own leaf at boot.
- **Trust bundle** — the per-scope set of CA intermediates a service trusts for the
  mesh (always `global`; a regional service adds its own region; a global service adds
  all regions). It is the membership allowlist: a peer whose chain validates against the
  bundle is a mesh member. Cross-region peers fail the chain.
- **Expected peer** — the `{service, scope}` an initiator pins for its specific mesh
  target (replacing the absent DNS-name check); a custom verifier asserts it against the
  peer's SPIFFE id and ignores the TLS SNI.
- **Scope-direction rule** — an acceptor's only authorization beyond bundle membership:
  a global acceptor admits any in-bundle scope; a regional acceptor admits only its own
  scope (and the node↔node forward plane additionally only `service == tunneller`).
- **Bootstrap endpoints** — the credential-minting endpoints (signup-code, enroll,
  token issue) that necessarily precede holding a JWT; each carries its own
  one-time-code / key-PoP check instead of the JWT layer.

## DNS reconciliation

- **Desired state** — what Tenants records a network *should* be (its
  provisioning state). Tenants is the single source of truth.
- **Provisioning state** — a network's lifecycle: `provisioning → active →
  deprovisioning`. (`deprovisioned` is not stored — it is the terminal transition
  that deletes the row.)
- **Provisioner** — the regional DDNS loop that drives `provisioning → active`. It
  is the **sole creator** of a network's DNS record: it publishes the record once
  an IP has been reported (a network with no IP yet is skipped until later), then
  reports `active`. To tolerate several regional replicas it **adopts-or-creates**
  the record and claims it with a compare-and-set (see `docs/adr/0003`).
- **Reaper** — the regional DDNS loop that drives `deprovisioning →` row-deletion by
  tearing the DNS record down.
- **Operational state** — the regional DDNS service's local record of what it has
  actually published for a network: its reported IP, the FQDN the provisioner
  published under, the Cloudflare A-record id, and any live ACME TXT-record ids.
  Keyed by network id, created lazily on the first IP report. It is an
  eventually-consistent cache — Tenants remains the single source of truth for
  desired state.
- **Report-IP** — the daemon's only contact with DDNS: it pushes its current public
  IP, which DDNS uses to **update the A record in place** (never to create one — see
  Provisioner). This is what keeps the record pointed at a daemon whose IP changes.
- **Work queue** — the mesh endpoints (`GET/PATCH /v1/networks`) the
  provisioner/reaper pull from and report back to.

## Tunnelling (tenant data plane)

- **Tunnel** — the long-lived reverse channel a daemon opens to the cloud so that
  inbound tenant traffic can reach a device that has no public inbound address. The
  daemon dials out and holds the channel open (days); the cloud pushes inbound
  connections back down it. TLS is never terminated in the cloud — the channel
  carries the daemon's own certificate end-to-end.
- **Tunneller** — the regional service that accepts tunnels and routes inbound
  tenant connections into them. It is a pure data plane: it owns no identity and no
  desired state, and resolves a network's slug from Tenants when a tunnel is
  established.
- **SNI passthrough** — the way inbound tenant TLS is routed without being
  decrypted: the Tunneller peeks the TLS `ClientHello` for the server name, maps the
  vanity slug to its tunnel, and forwards the still-encrypted stream (L4).
- **Node** — one Tunneller process. A region runs several active/active; a daemon's
  tunnel is held by whichever node it happened to dial.
- **Tunnel route** — the regional record of which node currently holds the tunnel
  for a given slug. Written when a tunnel connects, removed when it disconnects; a
  best-effort hint, since each node's live tunnels are the real source of truth.
- **Inter-node forward** — when an inbound connection lands on a node that does not
  hold the target slug's tunnel, it hands the raw stream to the node that does, over
  the private authenticated mesh. Keeps routing correct regardless of which node the
  connection or the tunnel landed on.
