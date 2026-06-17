# wardnet-cloud — domain glossary

The shared vocabulary for the cloud platform. Definitions only — no implementation
details. (See `docs/adr/` for the decisions behind these.)

## Identity & accounts

- **Tenant** — an account: an email, an [entitlement](#entitlement), and a
  subscription. The root of ownership. Lives in the global Tenants DB.
- **Network** — one wardnet network owned by a tenant. Holds a globally-unique
  **vanity slug** and a [provisioning state](#provisioning-state). The DNS record
  belongs to the network, not to any single device. A tenant may own several.
- **Daemon** — a device bound to a network, holding its own Ed25519 keypair. A
  network may have many daemons (active/active); each authenticates and is issued
  tokens independently.
- **Vanity / slug** — the network's public name (`<slug>.<zone>`); globally unique.
- **Entitlement** — the per-tenant limits a subscription grants: at minimum
  `max_networks` and `max_daemons`. Default for a self-service tenant: 1 / 1.

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
