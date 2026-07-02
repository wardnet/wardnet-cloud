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
- **Subscription** — the **license**: the provider-agnostic aggregate that **grants** a
  tenant's [entitlement](#entitlement). A tenant has a 1:N history with at most one
  **live** (non-canceled) row — its *current* subscription. Status is `trialing → active
  → past_due → canceled`. The free [trial](#trial) is itself a subscription row. Knows
  nothing about payment providers (that is [Billing](#billing)); owned by
  `SubscriptionService` in the `subscriptions` crate. See `docs/adr/0010`.
- **Billing** — *how* a subscription is paid for: the payment provider (Stripe today),
  hosted [Checkout](#checkout-session) (incl. `setup`-mode [card update](#payment-method-update)),
  the [plan-change](#plan-change) flow, the [plan catalog](#plan), [promotions](#promotion),
  the webhook, the idempotency ledger, and the provider-reference ids (the
  `billing_customers` table).
  Swappable; owned by `BillingService` in the `billing` crate. Drives the license only
  through the [SubscriptionCommands](#subscriptionreader--subscriptioncommands) port —
  Subscription never calls Billing back.
- **PaymentProvider** — the port behind which a concrete provider sits (`StripeGateway`
  today). Billing talks to the provider only through it, so the wire format never leaks
  into the lifecycle logic.
- **Plan** — a purchasable tier, defined as a Stripe Price whose metadata carries the
  `max_networks` / `max_daemons` it grants **and** a unique integer **`level`** that
  totally orders the catalog (used to decide upgrade vs downgrade). A price missing any
  of those keys — or with a duplicate `level` — is excluded from the catalog
  (safe-closed). Adding a plan is a Stripe change, no deploy.
- **Plan level** — the unique integer rank (`level` metadata) that orders [plans](#plan).
  A [plan change](#plan-change) to a higher level is an **upgrade**; to a lower level a
  **downgrade**; same level is rejected.
- **Plan catalog** — the set of purchasable [plans](#plan) + live [promotions](#promotion),
  owned by Stripe but served from a **projection**: a [Billing](#billing)-owned table a
  background worker keeps in sync with Stripe (webhook-triggered, with a periodic backstop).
  `GET /v1/plans` and server-side promo derivation read the projection, never Stripe on the
  hot path; the worker is its only writer (Stripe stays sole authority). Promo live-ness is
  computed against the clock at request time; a catalog past a hard staleness bound is
  refused (503). See `docs/adr/0011`.
- **Network** — one wardnet network owned by a tenant. Holds a globally-unique
  **vanity slug** and a [provisioning state](#provisioning-state). The DNS record
  belongs to the network, not to any single device. A tenant may own several.
- **Daemon** — a device bound to a network, holding its own Ed25519 keypair. A
  network may have many daemons (active/active); each authenticates and is issued
  tokens independently.
- **Daemon self-removal** — a daemon deleting **only its own** row from its network on
  teardown (uninstall / factory-reset / re-enrollment), via
  `DELETE /v1/networks/{id}/daemons/self` (network-scoped daemon JWT + PoP). The
  row-level effect is idempotent — removing an already-absent daemon still returns
  `204` — though each retry must be freshly re-signed (a byte-identical PoP replay is
  rejected). Unlike [Deregister](#deregister) it never tombstones the tenant,
  cancels the subscription, or tears down the network's DNS — those belong to the
  network and survive one device leaving. Distinct from the whole-network delete
  (`DELETE /v1/tenants/{id}/networks/{slug}`, which cascades **all** daemons + DNS).
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
  to a paid subscription. Also used in **`setup` mode** to collect/replace a
  [payment method](#payment-method-update) without a purchase.
- **Trial-preserving subscribe** — subscribing *from the [trial](#trial)* to a plan
  whose [entitlement](#entitlement) is **no greater** than the trial's (i.e. Home,
  `1/1`): the [Checkout session](#checkout-session) collects a card but defers the
  first charge to the tenant's original `trial_expires_at` (Stripe `trial_end`), so the
  user keeps their remaining free days and locks in the plan + any
  [promotion](#promotion). Entitlement is unchanged (still `1/1`). The subscription is
  a Stripe-side trial (`Active` locally — it entitles — with no managed-trial reaping).
- **Trial-ending change** — moving *while a trial is in effect* to a plan whose
  entitlement **exceeds** the trial's: the user is getting more capacity now, so the trial
  is forfeited and billing starts immediately (proration-free first charge). Covers two
  routes: (a) **subscribing** from the managed trial to Home HA / Pro; and (b)
  **[upgrading](#plan-change)** during a *trial-preserving* subscription (a Stripe-side
  trial) — because that subscription always sits on Home (`1/1`), any upgrade exceeds the
  trial entitlement and ends the trial (Stripe `trial_end` set to now). Both routes go
  through an account-plane **warning + confirmation** that names the trial days being
  forfeited. This is the only way a trial ends early.
- **Plan change** — an in-app move between [plans](#plan) on an *already-paid*
  subscription (`POST .../billing/change-plan`). An **upgrade** (to a higher
  [level](#plan-level)) applies immediately with proration on the next invoice; a
  **downgrade** (to a lower level) is scheduled via a Stripe Subscription Schedule to
  take effect at the current period end (the tenant keeps the paid-for entitlement
  until then). Re-entry reconciles against any pending schedule (release-then-act). An
  upgrade on a subscription still in its Stripe [trial](#trial) (a *trial-preserving*
  Home sub) is a [trial-ending change](#trial-ending-change): it ends the trial now and
  charges. A tenant on the *managed* (card-less) trial or `canceled` has **no Stripe
  subscription** to change — it subscribes via [Checkout](#checkout-session) instead.
- **Payment-method update** — replacing the card without leaving Stripe's trust
  boundary: a [Checkout session](#checkout-session) in `setup` mode. Recovery from
  `past_due` links the open invoice's Stripe-hosted pay page (`hosted_invoice_url`).
  There is **no Stripe Customer Portal** — all billing actions are in-app, with card
  entry always on a Stripe-served surface.
- **Promotion** — a global, seasonal discount auto-applied at [Checkout](#checkout-session)
  / [upgrade](#plan-change): a Stripe **coupon** flagged `wardnet_auto_apply` whose active
  window (`wardnet_promo_start` → Stripe `redeem_by`) contains now and whose
  `applies_to.products` covers the plan. Applied **server-side only** (never client-passed);
  surfaced on the catalog for display. Affects *cost* only — never [entitlement](#entitlement).
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
  FK-cascading the tenant's subscriptions, daemons, codes, pending enrollments, and
  the [Identities aggregate](#identities-aggregate)'s login methods + sessions.
  N-replica-safe and idempotent.

## Eventing & reconciliation

- **Domain event** — a signal a service raises so another aggregate can react, instead
  of one service reaching into another's repository (`TenantCreated`,
  `TenantDeregistered`, `SubscriptionDeactivated`). Best-effort delivery; the
  [reconcile](#reconcile) is the guarantee. Serde-serializable with a versioned wire
  format. See `docs/adr/0007`, `docs/adr/0010`.
- **EventBus / EventStream** — the transport-free **port** domain events flow through:
  `publish(&event)` + `subscribe(group) -> EventStream` (no `tokio` type in any
  signature). One in-process adapter today; a durable broker (using `group` for
  competing consumers across replicas) drops in later with no reactor change. Supersedes
  the in-process-only "broadcast bus" framing.
- **SubscriptionReader / SubscriptionCommands** — the synchronous query/command **ports**
  over the [license](#subscription) aggregate (in `wardnet_common`). `SubscriptionReader`
  = entitlement reads (`current` / grace-aware `is_active`); `SubscriptionCommands` = the
  one-way [Billing](#billing) → Subscription write edge (`convert_trial_to_paid` /
  `update_paid` / `mark_past_due` / `cancel`). In-proc adapter = a direct call; a
  mesh-mTLS HTTP adapter later. The crates depend on these ports, never on each other.
- **Reactor** — a long-running loop subscribed to the event bus that turns a domain
  event into a call on the **owning** service's method (e.g. `TenantCreated` →
  `SubscriptionService::create_trial`; `SubscriptionDeactivated` →
  `TenantsService::deprovision_networks_for`). Idempotent, so a redelivery is harmless.
- **Reconcile** — the periodic safety net that re-derives desired state for any dropped
  event: it backfills a missing trial and deprovisions an unsubscribed tenant's networks.

## Enrollment credentials

- **One-time code / verification code** — a short-lived, single-use, email-proving
  credential, issued via the unified `POST /v1/verification-codes {email, purpose}`
  resource. Its [purpose](#code-purpose) binds it to exactly one flow. Within
  `enrollment`, a *new-signup* code (no tenant yet) or an *add-daemon* code (existing
  tenant). Consumed once.
- **Code purpose** — the flow a [one-time code](#enrollment-credentials) is bound to:
  `signup` (web password signup), `password_reset` (web password reset), or `enrollment`
  (daemon enroll). A code is consumable by exactly its own purpose, so a code issued for
  one flow can never be replayed against another. (The old `/v1/enrollment-codes` and
  `/v1/auth/password/reset-code` endpoints are removed; see `docs/adr/0009`.)
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
