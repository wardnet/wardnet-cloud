# wardnet-cloud agent guide

Conventions and invariants for agents working inside `source/`.

> **WS-C re-scope (2026-06-16):** the Tenants service was rebuilt to the end-state
> **tenant → network → daemon** model with a `provisioning_state` lifecycle, and auth
> was unified into `common::auth::authenticate(CallerType)` (`SERVICE` via mTLS /
> `DAEMON`/`USER` via JWT). PoW self-registration and the `introspect` endpoint are
> gone; DNS is now reconciled from desired state via a mesh work-queue
> (`GET/PATCH /v1/networks`). See `CONTEXT.md` (glossary) and `docs/adr/0001`,
> `docs/adr/0002`.
>
> **WS-D (2026-06-17):** `crates/cloud` was carved into **`crates/tunneller`** (the
> multi-node SNI-passthrough reverse-tunnel edge) and **re-added to the workspace**;
> the DDNS code it still held was deleted (it lives in `crates/ddns`). All API
> request/response DTOs were rehomed into **`common::contract`** (invariant #21). See
> `docs/adr/0004` and invariants #2/#10/#11/#12/#18 (now reworked to the live
> Tunneller).
>
> **WS-E (2026-06-17):** mesh mTLS is now **SPIFFE-verified, bundle-anchored, and
> hot-reloaded** to match the inforge contract. Leaves carry a SPIFFE URI SAN only
> (`spiffe://<trust_domain>/<env>/<scope>/<service>`, **no DNS SAN**); trust is a
> per-scope **bundle of intermediates**; the files (`MTLS_LEAF_CERT_PATH` /
> `MTLS_LEAF_KEY_PATH` / `MTLS_TRUST_BUNDLE_PATH`) are re-projected in place on renewal
> and each service file-watches + hot-reloads them. Authorization = bundle membership +
> a scope-direction rule (no per-peer-service allowlist); initiators pin an
> `ExpectedPeer{service,scope}`. `ServiceIdentity` is now structured
> `{trust_domain,env,scope,service}`. See `docs/adr/0005` and invariants #18/#19.
>
> **WS-K (2026-06-20):** cloud-side OpenTelemetry observability landed. Logs + metrics + traces
> ship over OTLP to Grafana Cloud (free tier); the backend is a single env var so it is
> **vendor-neutral** and **opt-in** — with `OTEL_EXPORTER_OTLP_ENDPOINT` unset the services
> keep their prior stdout-JSON behaviour unchanged. Each service now calls
> `wardnet_common::telemetry::init(service_name, version)` in `main` (replacing the hand-rolled
> `tracing_subscriber` registry) and holds the returned `TelemetryGuard` for the process
> lifetime (Drop flushes via `shutdown_with_timeout(3 s)`). A shared
> `telemetry::install_http_layers(router)` mounts RED-metrics middleware + inbound
> `traceparent` extraction + an INFO-level TraceLayer on every service router. Domain meters
> added: tenants tombstone-sweep counters, a ddns provisioned counter, and a tunneller
> active-tunnel gauge. Outbound `traceparent` injection for distributed traces: DDNS
> work-queue and Tunneller mesh client each call `telemetry::inject_trace_context`. See
> invariants #26 and #27.

> **WS-G (2026-06-18):** billing landed. Entitlement is **granted by a `subscriptions`
> aggregate** (not the tenant — `tenants` is identity-only now), with a card-less
> managed **trial** + grace windows; **Stripe** drives the paid lifecycle (webhook +
> checkout/portal), entitlement from price metadata; **Resend** emails enrollment codes.
> Cross-aggregate side-effects flow through **in-process domain events + reactors**
> (`wardnet_common::event`) — no service touches another aggregate's repository. See
> `docs/adr/0006`, `docs/adr/0007`, and invariants #22/#23/#24.

> **WS-F (2026-06-19):** the human **web login** front door + JWT **`aud`** grant-scoping
> landed. Tenants-signed JWTs now carry `aud` (a set of mesh service names); each service's
> `Verifier` validates **its own name** (`tenants`/`ddns`/`tunneller`), so a token is
> accepted only at the services it was minted for — a user token is `[tenants]`, a
> network-scoped daemon `[tenants, ddns, tunneller]` (ADR-0008). Login methods + browser
> sessions are a **second segregated aggregate** in the `tenants` crate, owned by
> `IdentitiesService` (password argon2id + Google OIDC + GitHub OAuth2 behind one trait;
> a verified-email two-gate resolver; a revocable server-side `sessions` row behind an
> httpOnly cookie → silent `POST /v1/auth/token` exchange → a **5-min** `USER` JWT). The
> auth layer stays pure-JWT (#18). `POST /v1/tenants` (`register_tenant`) is **deleted** —
> account creation now happens only at a credential-proving moment. See `docs/adr/0008`,
> `docs/adr/0009`, and invariants #2/#18/#23/#25.

> **Status:** every invariant below is **live on `main`**. The earlier `[#444]`/`[#445]` planning
> tags are retired — the SNI/tunnel data plane (WS-D), PostgreSQL/Neon, the multi-node `TunnelRouter`
> (`LocalRouter`, its sole impl, already does inter-node forwarding), and the inforge-injected env
> secret model have all landed. Production secret provisioning (inforge resolving from Infisical and
> injecting env vars / tmpfs key files) is a deployment contract owned by the **infrastructure repo**,
> not pending code in this workspace (invariant #9).

## Workspace layout

`source/` is a Cargo workspace (`source/Cargo.toml`, `resolver = "3"`, edition 2024) with six members:
the four service crates (`common`, `tenants`, `ddns`, `tunneller`) plus two non-published support members
— `xtask` (dev tooling, incl. the `gen-certs` mesh cert generator) and `end2end-tests/mesh` (a docker-compose
e2e scenario; see "Cross-service end-to-end tests" below):

- **`crates/common`** (lib `wardnet_common`) — everything genuinely cross-service: `token`, `mtls`,
  `proxy_protocol` (incl. `client_ip`), `replay_cache`, `dns_provider`, `db` (`DbPools` / `connect`),
  `error` (`ApiError` / `ErrorBody`), `validation`, the generic `auth` core (the `authenticate(CallerType)`
  middleware — body guard, JWT verify, caller-type + `aud` gate, daemon Ed25519 PoP over the canonical
  payload, replay cache — each service's `AppState` implements `AuthContext` to supply its `verifier()` +
  `replay_cache()`), `serve` (`run_api`, the PROXY-required plain-HTTP listener, plus a
  stream-generic `connection`), `mtls` (SPIFFE mesh mTLS: `SpiffeId`/`ExpectedPeer`, the SNI-ignoring
  `client_config_from_pem`/`mesh_client` initiator side, `server_config_from_pem` + `peer_spiffe_id`
  acceptor side, the hot-reload holders `MeshClient`/`ReloadableServerConfig`, and `watch_mesh_files`),
  the in-process `event` bus (`EventPublisher` / `BroadcastEventBus` / `DomainEvent` — the
  cross-aggregate decoupling substrate, invariant #23), generic `health::register`, the
  env-`config` helpers, and `telemetry` (OTLP init + HTTP middleware — see invariants #26/#27).
  (The old `pow` module is gone — enrollment is now a one-time email code, ADR-0009.)
- **`crates/tenants`** (bin `wardnet-tenants`, lib `wardnet_tenants`) — the global identity/naming
  service, carved out of `cloud` in WS-B. Owns the tenant/network/daemon/enrollment repos, the JWT
  `Signer`, `TenantsService`, and the **global Tenants DB** (its `migrations/` — moved from cloud's
  `migrations-global/` — and its own `db::init` with a crate-relative `sqlx::migrate!`), plus its own
  `config`/`state`/`error`. Serves a **public** nginx-fronted router whose routes are grouped by the
  caller kind they accept (each authenticated group wrapped in `authenticate(CallerType)`): a
  **bootstrap** group (`health`, daemon `enroll` + `token` issue, signup `codes`, the Stripe `billing`
  webhook, and the web `auth` login surface — each verifying its own one-time-code / key-PoP /
  signature / cookie), an `availability` check (DAEMON·USER), register-`network` (DAEMON), and the USER
  account plane (`tenants`, including `deregister`), **plus** a separate **internal mesh-mTLS**
  reconcile listener (`src/mesh.rs` — mTLS transport only; handlers in `src/api/reconcile.rs`,
  `GET/PATCH /v1/networks`) with no JWT layer. Account deregister (`DELETE /v1/tenants/{id}`, USER,
  owner-checked, 202, idempotent) **tombstones** (`deregistered_at`) rather than deleting: it cascades
  the tenant's networks to `deprovisioning` (the DDNS reaper does DNS teardown — invariant #19) and
  cancels the subscription, and a periodic **sweep loop** (`TENANT_SWEEP_INTERVAL_SECS`, default 3600,
  N-replica-safe) FK-cascade-deletes tombstoned tenants once their networks are gone. The email is freed
  for a fresh signup the moment the tombstone is set — a **partial unique index** (`email WHERE
  deregistered_at IS NULL`) means only live tenants reserve it, and a tombstoned tenant is
  rejected up-front at **every** growth path — `mint_jwt` (token refresh), `issue_tenant_code`
  (add-daemon code minting), `enroll`, **and the USER login/exchange plane** (`create_session` calls
  `TenantsService::tenant_is_live`; `exchange_session`'s `touch_and_get_tenant` SQL includes
  `deregistered_at IS NULL`) — so a deregistered-but-not-yet-swept account can never mint a token
  or grow a daemon, and the USER plane closes the reactor-lag revocation gap without waiting for the
  identities reactor to purge the session row. **Billing (WS-G):** a separate `SubscriptionService` owns the `subscriptions`
  aggregate (entitlement source, trial + grace, Stripe lifecycle via the `stripe` `StripeGateway`); a
  `subscription` + `network` **reactor** apply `wardnet_common::event` domain events (invariants
  #22/#23); the `email` `EmailSender` (Resend / dev no-op) sends enrollment codes. **Web auth (WS-F):**
  a third segregated aggregate, `IdentitiesService` (`src/identities.rs`), owns the `tenant_identities`
  + `sessions` repos and the human login plane — password (argon2id) + Google OIDC + GitHub OAuth2 behind
  the `ExternalIdentityProvider` trait, the verified-email two-gate resolver, cookie sessions → the 5-min
  `USER` JWT exchange (`src/api/auth.rs`, the bootstrap group) + `GET /v1/me` (USER); an `identities`
  reactor purges sessions/identities on `TenantDeregistered` (invariants #23/#25). Depends on
  `wardnet_common`, `reqwest`, `hmac` (Stripe webhook signatures), `argon2`, `axum-extra` (cookies), `openidconnect`, `time`.
- **`crates/ddns`** (bin `wardnet-ddns`, lib `wardnet_ddns`) — the regional DNS reconciler, carved out
  of `cloud` in WS-C. A stateless controller that drives Cloudflare toward the desired state Tenants owns
  (ADR-0001): a short-interval **provisioner** + long-interval **reaper** (`src/reconcile.rs`) that drain
  the Tenants mesh **work-queue** (`src/work_queue.rs` — `WorkQueue` trait + the mTLS-backed
  `TenantsWorkQueue`), plus daemon-facing **report-IP** and **ACME** endpoints (`src/api/`). Owns the
  regional `operational` DB (its `migrations/` + crate-relative `db::init`), the `DdnsService`, and the
  ported `CloudflareDnsProvider` (`src/cloudflare/`). Its write model is hybrid (ADR-0003). Auth is
  **route-layer** `authenticate(CallerType::DAEMON)`, **not** the `/v1/installs/` path-gate (#2): the
  target network is the JWT `net` claim, so a daemon can only ever touch its own network. Depends on
  `wardnet_common`.
- **`crates/tunneller`** (bin `wardnet-tunneller`, lib `wardnet_tunneller`) — the regional
  **SNI-passthrough reverse-tunnel edge**, carved from `cloud` in WS-D and finished to its multi-node
  end state. A daemon dials `GET /v1/tunnel` (network-scoped JWT, route-layer `authenticate(DAEMON)`)
  and keeps a WebSocket open; the node forwards inbound L4 TLS arriving at its **SNI demuxer** (`sni`)
  down that tunnel via a `TunnelRouter` (`router`) over the per-node `tunnel` registry. Multi-node from
  the ground up: a regional Postgres `tunnel_routes` map (`repository`), a private mesh-mTLS inter-node
  `forward` + a `TenantsClient` routing-policy reader (`mesh`), and a pull-reconcile abort + TTL reaper
  (`reconcile`). Auth is **JWT-only** (the identity DB lives in Tenants); the routing policy reads
  Network/Tenant over mesh mTLS. Owns its own `config`/`db`/`state`/`error` over common. Depends on
  `wardnet_common`. See `docs/adr/0004`.

**Where code goes:** if a primitive is (or will be) used by more than one service, it belongs in
`common`; service-specific logic stays in its service crate (`tenants`/`ddns`/`tunneller`). **Every API
request/response DTO lives in `wardnet_common::contract`** (the whole wire surface — bootstrap, daemon,
account, mesh, all of it), shared by the producer and the consumer so a producer-side change is a compile
error on the consumer; `ErrorBody` is the precedent (see invariant #21). The producer keeps its
`impl From<DomainType> for ContractDTO` mapping locally (the orphan rule allows it — the domain type is
local). Shared dependencies and lints are declared once at the
workspace root — add deps via `workspace.dependencies` and reference them with `<dep>.workspace = true`;
do not pin versions per-crate. Lints come from `[workspace.lints.clippy]` (pedantic) via
`[lints] workspace = true` in each member.

## Must-know invariants (never violate these)

1. **Opaque credentials are stored only as hashes, never raw.** There is no daemon bearer token any more — daemons authenticate with a JWT + Ed25519 PoP and their device key never leaves the device (#2/#18). The opaque secrets that *are* persisted are stored hashed: one-time enrollment codes and browser session tokens as `hex(SHA-256(value))` (`tenants::util::random_token` mints the raw value, `sha256_hex` is the only form written — `enrollment_codes.code_hash`, `sessions.token_hash`), and passwords as an argon2id PHC string (`tenant_identities.secret_hash`). The raw value is returned/shown exactly once at issuance and is never persisted, logged, or echoed. See invariant #25 (the web-auth extension of this rule).

2. **Auth is a route-layer caller-type guard plus `aud` grant-scoping, not a path-gate.** Every authenticated route group is wrapped in `authenticate(CallerType)` (`common::auth`), which resolves the caller (SERVICE via mTLS / DAEMON · USER via JWT+PoP) and rejects anything outside the allowed set. **Caller-type is no longer the only JWT gate**: each service's `Verifier` is built with its own mesh name as the expected **`aud`** and rejects any token whose `aud` omits it (ADR-0008), so "any envelope-valid token of the right caller type is accepted by any service" is **retired** — a user token (`aud:[tenants]`) is rejected at ddns/tunneller, and a not-yet-network-bound daemon token (`aud:[tenants]`) has no reach into the data plane. There is **no `/v1/installs/` path prefix** any more — DDNS report-IP/ACME and the Tunneller `GET /v1/tunnel` are all route-layer `authenticate(DAEMON)`, scoped to the JWT `net` claim, so a daemon can only ever touch its own network. (The legacy `auth_layer` opaque-bearer path-gate is retired with the old `cloud` bin.)

3. **Slug allocation and entitlement limits are one atomic operation.** `TenantsService::register_network` binds the new network **and** its first daemon in a single `NetworkRepository::register_network` transaction that enforces global slug uniqueness *and* the subscription's `max_networks` / `max_daemons` together, returning a typed `RegisterNetworkOutcome` (`Created` / `SlugTaken` / `NetworkLimit` / `DaemonLimit` / `DaemonExists`) — never a partial write to roll back. There is **no PoW challenge** and **no cross-database saga**: the old `register.rs` `names().reserve()` → `challenges().consume()` ordering and the global-`names` + regional-`installs` two-DB saga are gone. Enrollment is now a one-time email code consumed atomically (`enrollment.enroll`, ADR-0009), and networks/daemons live in the one global Tenants DB.

4. **ReplayCache keyed on `{daemon-public-key}:{timestamp}:{body_hash}`.** The replay subject is the daemon's token `sub` — its standard-base64 Ed25519 public key (`== cnf`), the daemon's stable identity, **not** a DB row id. The key is built in exactly one place (`verify_pop_request` in `common::auth`). Do not change the format without updating the replay window constant and tests. The window is ±120 s (`REPLAY_WINDOW_SECS`, double the ±60 s timestamp window) for clock-skew at the cache boundary.

5. **Body buffered before auth.** The 1 MiB body guard (`MAX_BODY_BYTES`) runs for _every_ request through the `authenticate` middleware, including unauthenticated ones. Buffering the body is the first thing `authenticate` does — before the JWT verify or any DB/mesh call (it is also needed to hash the body for daemon PoP).

6. **Long-lived keys are parsed once at load, not on the hot path.** A service decodes the Tenants JWT **verify key** from PEM exactly once, when it builds its `Verifier` (`Verifier::from_pem`, at boot), and reuses the `DecodingKey` for every `verify` — never re-parse it per request. (There is no `installs` row any more: a daemon's PoP public key rides in the token's `cnf` claim and is decoded per request via `Claims::pop_public_key()` into `[u8; 32]` — it is carried in the verified token, not loaded from the DB, so there is nothing to cache. The daemon's `sub` *is* that base64 key.)

7. **Canonical payload includes `path_and_query`.** The Ed25519 signature covers `"METHOD\npath_and_query\ntimestamp\nhex-sha256(body)"`. Use `uri.path_and_query()`, not just `uri.path()`, so query parameters are authenticated.

8. **X-Forwarded-For only from loopback peers.** `client_ip()` (in `wardnet_common::proxy_protocol`) trusts the header only when `addr.ip().is_loopback()`. Never call `headers.get("X-Forwarded-For")` directly in a handler. The real peer address comes from the PROXY v1 header threaded in as `ConnectInfo` (see #13), not from the kernel socket.

9. **Secrets arrive as environment variables injected by inforge; never hard-code, persist, or log them.** In production inforge resolves every secret from Infisical and injects it into the process environment — `DATABASE_URL`/`GLOBAL_DATABASE_URL`, the Cloudflare token, the Stripe/Resend keys, the OAuth client secrets — read once at startup via `wardnet_common::config::required` (`Config::from_env`). Secret **material** (the JWT signing/verify keys, the mesh leaf cert/key + trust bundle) is projected onto tmpfs by inforge with only the file *path* passed in the env (`*_KEY_PATH`/`*_BUNDLE_PATH`, read via `read_secret_file`); the key bytes never appear in an env var. Never hard-code a prod secret, never write a resolved secret to disk, never log one — `Config`'s `Debug` redacts them. Dev/test use dummy values. (There is **no runtime `SecretsProvider` trait**: the earlier Infisical-fetch-at-runtime design was folded into inforge-injected env — secrets are sourced from Infisical *by inforge*, then handed to the process as env vars.)

10. **(retired)** The old per-install **nonce challenge** for the tunnel upgrade is gone. `GET /v1/tunnel` is route-layer `authenticate(DAEMON)`: the per-request Ed25519 **PoP** that the auth layer enforces on the upgrade GET already proves possession of the daemon's `cnf` key, so a separate server-nonce challenge is redundant. The `into_parts`/`from_parts` in the middleware preserve the `OnUpgrade` extension, so the WebSocket upgrade survives the layer (proven by `tunneller/tests/api.rs`).

11. **Route inbound streams only through `TunnelRouter`.** The SNI demuxer (`tunneller/src/sni`) hands every stream to the `TunnelRouter` trait keyed on **vanity slug** — never look up the in-memory `TunnelRegistry` `DashMap` directly outside `LocalRouter`. `LocalRouter` short-circuits slugs this node owns into the registry and forwards everything else over the private inter-node mesh link to the `node_addr` in `tunnel_routes`. A node `upsert`s its ownership on tunnel connect and deletes it on disconnect (own-node-guarded). The table is a **hint**: each node's live registry is the source of truth, so a forward to a node whose registry no longer holds the slug **fails closed** (the connection is dropped, not mis-routed). See `docs/adr/0004`.

12. **The tunnel registry is in-memory and per-node.** It is not persisted; after a node restart all daemons reconnect. Registration is keyed on slug with a per-tunnel **abort token** (`CancellationToken`) + a generation so a reconnect cleanly displaces a stale handler and a superseded handler's cleanup is a no-op. The inter-node `forward` listener is **private mesh-mTLS only** (it bypasses SNI, so it must be authenticated — the handshake *is* the auth); a peer reads a `{slug, dest_port}` preamble then splices the raw L4 stream into the local registry. Treat `conn_id` as wrapping (`u32`). A live tunnel is torn down by the **pull-reconcile abort reaper** (per-node, ADR-0004) when its network is `404`/`deprovisioning` or its subscription lapses; the same pass heartbeats `last_seen`, and a TTL reaper purges rows orphaned by a crashed node.

13. **Strip the PROXY v1 header first, consuming exactly the line.** Every public listener is fronted by nginx with PROXY protocol v1. Read the header byte-by-byte up to its CRLF and **no further** (`proxy_protocol::read_required`/`read_optional`) — never a `BufReader`, which would swallow the `ClientHello` and break the SNI peek. The recovered client IP must be threaded into the API as `ConnectInfo` so the per-IP rate limiters (signup-code issuance, password login) keep working — handlers read it via `proxy_protocol::client_ip` (#8). On the API listener the header is **required** and **fail-closed**: a connection with a missing/invalid header, a read timeout, or a `PROXY UNKNOWN` family is **dropped** rather than served against nginx's loopback address (which would let `client_ip()` trust a spoofable `X-Forwarded-For`). See `serve::run_api` in `crates/common/src/serve.rs` (used by every service's `main.rs`).

14. **The control-plane API is served over plain HTTP behind nginx.** It listens on `config.api_listen_addr` (public `:80`, fronted by nginx which terminates TLS) and serves `/v1/health` + the API. There is no in-process TLS for the API any more — do **not** add a rustls/TLS-terminating branch to the API listener. The SNI listeners (`https_listen_addr`/`dot_listen_addr`) are **passthrough-only**: `sni::run(...)` forwards to the tenant tunnel on `dest_port` 443 / 853 and never inspects or terminates the inner TLS.

15–17. *(historical — deleted machinery, kept only as a pointer)* The old in-app TLS-termination + HTTP-01-ACME subsystem (`tls/`, `acme/`, `sweep/`, `http01.rs`, `crypto.rs`, `repository/tls.rs`, the `bridge_tls` table + `bridge_tls_lease`, `ENCRYPTION_KEY`, the `GET /.well-known/acme-challenge/{token}` responder, and the SNI-terminate branch) has been **removed**. Public TLS + ACME are now an inforge-injected **nginx sidecar**, the control-plane API is plain HTTP behind it (#14), and the tenant data plane is pure **L4 SNI passthrough** — Tunneller never terminates. (DDNS still serves daemon-facing **DNS-01** ACME TXT endpoints — that is a different, live path; see #20 and ADR-0003.)

18. **Two auth planes: JWT for external daemons, mTLS for the mesh.** External daemon/user requests (via nginx) authenticate with an identity JWT (Tenants-signed, verified offline) plus, for daemons, the Ed25519 PoP — all via route-layer `authenticate(DAEMON|USER)`. **Inter-service / mesh-plane calls carry no JWT** — they authenticate by **SPIFFE-verified** mutual TLS: a client cert chained to the per-scope **trust bundle** whose URI SAN parses to a `ServiceIdentity{trust_domain,env,scope,service}` that `authenticate(SERVICE)` accepts. Mesh leaves carry a SPIFFE URI SAN only (**no DNS SAN**), so initiators pin an `ExpectedPeer{service,scope}` in a custom verifier that **ignores the SNI** (`mtls::client_config_from_pem`/`mesh_client`), and acceptors enforce a **scope-direction rule** on the parsed peer id (global acceptor → any in-bundle scope; regional acceptor → peer scope == own scope) instead of a per-peer-service allowlist (the bundle is the allowlist). Rotated material hot-reloads in place (ADR-0005). The **Tunneller spans both**: it is a JWT-only daemon endpoint (`GET /v1/tunnel`) *and* a mesh-mTLS client (its routing policy reads Tenants' `GET /v1/networks/{id}` · `GET /v1/tenants/{id}`, and its nodes forward to each other over a private mesh-mTLS link whose acceptor additionally pins `service == tunneller`). Every JWT now carries an **`aud`** grant claim each verifier checks against its own name (ADR-0008, invariant #2). **Humans authenticate to a third plane (WS-F, ADR-0009):** a revocable server-side `sessions` row behind an httpOnly cookie is the durable web credential; the SPA calls `POST /v1/auth/token` to silently exchange it for a short-TTL (5-min) `USER` JWT (`aud:[tenants]`, `sub = tenant_id`). The auth layer itself **stays pure-JWT** — it never learns about cookies; the cookie↔JWT exchange lives entirely in `IdentitiesService` / `api/auth.rs` (the bootstrap group). "Am I logged in?" is answered by *attempting the mint*, not by reading the (httpOnly, unreadable) cookie.

19. **The mesh work-queue is mTLS-only and off the public router.** The reconcile work-queue (`GET/PATCH /v1/networks`, Tenants ↔ DDNS provisioner/reaper) is served by a separate internal listener on `config.mesh_listen_addr`. **Transport vs API are split:** the mTLS listener lives in `crates/tenants/src/mesh.rs` (`serve_mesh` — TLS acceptor + accept loop + semaphore), and the SERVICE-plane handlers + DTOs live in `crates/tenants/src/api/reconcile.rs` (`pub fn router`). "mesh" names the mTLS *transport*, never a route group. The reconcile router is **not** mounted on the public nginx-fronted router and carries `authenticate(SERVICE)` — the mutual-TLS handshake (server presents the mesh leaf via the hot-reloadable `mtls::ReloadableServerConfig`, requires a client cert chained to the trust bundle via `mtls::server_config_from_pem`; the accept loop then parses the peer's SPIFFE id with `mtls::peer_spiffe_id` and stamps the structured `ServiceIdentity`, applying the global-acceptor scope rule) is what `SERVICE` resolves against. Never expose the reconcile routes on the public router or add a JWT/bearer layer to them. (`POST /v1/introspect` is gone — DNS teardown is the DDNS reaper draining this work-queue, per ADR-0001.)

20. **DDNS A-record creation is the provisioner's alone, and is adopt-or-create + CAS.** Only `DdnsService::provision` (the provisioner) creates a Cloudflare A record; **report-IP only ever updates in place** (`OperationalRepository::record_ip` writes the `ip` column only — never `fqdn`/`cf_a_record_id`), so a daemon's IP report can never resurrect a record the reaper just deleted. To tolerate N regional replicas, `provision` adopts an existing record for the FQDN or creates one, then CAS-claims the id (`WHERE cf_a_record_id IS NULL`); on a lost CAS it deletes its record **only if** that record is not the one the winner stored. Do not add a create path to report-IP, and do not drop the `cf_a_record_id IS NULL` guard on the claim. See ADR-0003.

21. **Every API request/response DTO lives in `wardnet_common::contract`, shared by producer and consumer.** A DTO defined in the producing service and re-declared (a "deserialize twin") in the consumer drifts silently; instead both crates depend on the one type in `common::contract`, so a producer change is a compile error on the consumer (`ErrorBody` is the original precedent). This covers the whole wire surface — bootstrap/daemon/account/mesh DTOs alike — including the embedded value objects (`ProvisioningState`, `SubscriptionStatus`, `Entitlement`), which also double as Tenants' DB-domain enums (their `as_str`/`from_db` helpers live on the contract type). A resource view (`NetworkView`/`TenantView`/`DaemonView`) is the **full** resource, never trimmed to one caller's current needs; tolerant consumers read only the fields they use. The `impl From<DomainType> for ContractDTO` conversion stays in the owning service crate (orphan-rule-legal, since the domain type is local). Do **not** add a second copy of a DTO in a service crate, and do not narrow a view to a caller.

22. **Entitlement is granted by the current subscription, never the tenant.** The `tenants` row is identity-only; all billing/entitlement state lives on the `subscriptions` aggregate (1:N history, one live row per tenant via the `uq_subscriptions_live` partial unique index; the free trial is itself a `trialing` row). `mint_jwt` / `register_network` read the entitlement + `is_active` (trial / payment grace) via `SubscriptionService::current` — a service method, never the subscription repo. The status enum's `from_db` maps unknown → `Canceled` (**safe-closed**: an unknown billing state must not grant service), and a webhook with missing price metadata **declines to grant** rather than guessing. See `docs/adr/0006`.

23. **A service holds only its own aggregate's repositories; cross-aggregate side-effects flow through domain events + idempotent reactors — never a foreign repository and never a direct cross-aggregate write.** `TenantsService` (tenants/networks/daemons/enrollment) must **never** hold `SubscriptionRepository`; `SubscriptionService` must **never** hold `NetworkRepository`. Reads are direct *service-method* calls (`TenantsService` → `SubscriptionService::current`, a one-way edge); write-side side-effects are published as `DomainEvent`s (`wardnet_common::event`) and applied by reactors that call the **owning** service's method (`TenantCreated` → `create_trial`; `SubscriptionDeactivated` → `deprovision_networks_for`). The broadcast bus is best-effort, so reactors are idempotent and a periodic `TenantsService::reconcile` is the dropped-event safety net (backfill a missing trial / deprovision an unsubscribed tenant). **`IdentitiesService` (WS-F) is a third segregated aggregate on this exact pattern:** it holds **only** the `tenant_identities` + `sessions` repositories, reads/create-delegates via `TenantsService` method calls (`find_tenant_by_email` / `register_tenant` / `consume_signup_code` — a one-way `IdentitiesService → TenantsService` edge), and the reverse side-effect is the **identities reactor** reacting to `TenantDeregistered` → `IdentitiesService::purge_for` (delete the tenant's sessions + login methods; the FK cascade covers the hard sweep). It must **never** hold the tenant/network/daemon/subscription repositories. See `docs/adr/0007`, `docs/adr/0009`.

24. **Stripe is reached behind the `StripeGateway` trait; the webhook is a self-verifying bootstrap endpoint.** A hand-rolled `reqwest` client (`crates/tenants/src/stripe.rs`, the same pattern as GitHub `OAuth2` — workspace stays openssl-free) is the production gateway; tests use a recording fake, so `SubscriptionService` (and `apply_stripe_event`) never touch the Stripe wire format. Webhook signatures are verified **in-process** (`stripe::verify_signature`: HMAC-SHA256 over `"{t}.{payload}"`, constant-time compare via `hmac::Mac::verify_slice`, ±5-min timestamp tolerance — unit-tested in `stripe::tests`). `POST /v1/billing/stripe/webhook` carries no JWT layer — the **`Stripe-Signature` header is the credential**, verified in the handler (`security(())`), and applies idempotently via the `processed_stripe_events` ledger (Stripe redelivers). A handled event whose object **fails to deserialize is an error, never a silent `Ignored`** — the ledger records only events whose effect landed, so a parse failure must surface (non-2xx → Stripe retries) rather than be marked permanently processed; `normalize_event` is robust to Stripe API-version drift (reads `current_period_end` from the subscription **or** its item, and the invoice subscription ref from the top level **or** `parent.subscription_details`). Stripe API/response error bodies are never logged verbatim (only the status + machine-readable `type`/`code`, per invariant #9). Stripe/Resend secrets (`STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` / `RESEND_API_KEY`) arrive in the env via inforge like the DSN, are redacted in `Config`'s `Debug`, and use dummies in dev/test.

25. **Web auth: session-cookie anchor, minted-JWT API, verified-email two-gate, store only hashes.** A `USER` principal **is** the tenant (1:1, `sub = tenant_id`); a human's login methods (`password` = argon2id, or a linked `google`/`github`) are rows in `tenant_identities`, each resolving to its tenant by a **provider-verified email** with two gates (gate 1: `email_verified` / a one-time code proves the inbox; gate 2: match→auto-link, no-match→web-first signup via `TenantsService::register_tenant`). Tenant creation therefore **only ever happens at a credential-proving moment** — never under `USER` auth (`register_tenant`/`POST /v1/tenants` is gone). The browser credential is a revocable server-side `sessions` row behind an httpOnly+Secure+SameSite cookie (30-day sliding, `axum-extra` private jar); the SPA exchanges it via `POST /v1/auth/token` for a 5-min `USER` JWT held only in memory. **Revocation (deleting the session row), not JWT TTL, is the primary hijack defence**; password-reset and deregister both force-logout by deleting the tenant's sessions. A **deregistered tenant can never receive a new session or exchange an existing one**: `create_session` pre-checks `TenantsService::tenant_is_live`, and the `touch_and_get_tenant` SQL adds `deregistered_at IS NULL` so the exchange is live-tenant-only even before the identities reactor purges the row. **Password login is throttled per source IP** (in-memory, `LOGIN_ATTEMPTS_PER_IP` attempts per `LOGIN_WINDOW_SECS`-second window in `IdentitiesService`; `IdentitiesError::RateLimited` → HTTP 429); this is defence-in-depth per replica, not a distributed quota. **Store only hashes** (invariant #1, extended): `sessions.token_hash` is `hex(SHA-256(token))` and `tenant_identities.secret_hash` is an argon2id PHC string — never the raw token or password, never logged or echoed. Federated login is backend-orchestrated with `state`/PKCE in a short-lived signed cookie; Google (full OIDC, `openidconnect`) and GitHub (OAuth2, `reqwest`) sit behind the `ExternalIdentityProvider` trait. Cookie key + OAuth client secrets are inforge-injected, redacted in `Config`'s `Debug`, dummies in dev/test. See `docs/adr/0009`.

26. **Observability is opt-in by `OTEL_EXPORTER_OTLP_ENDPOINT`; the OTLP auth credential comes from a tmpfs file, never an env var.** Call `wardnet_common::telemetry::init(service_name, version)` once in `main` and hold the returned `TelemetryGuard` for the process lifetime — it flushes the final OTLP batch on Drop. With the endpoint env var unset the call is a no-op (stdout JSON logging only, exact prior behaviour). The Grafana Cloud Basic-auth credential (`instanceID:token`) is read from the tmpfs file pointed to by `OTEL_AUTH_TOKEN_PATH` via `config::read_secret_file` (consistent with invariant #9 — no secrets in env). Logs and traces are filtered on **independent** axes: `RUST_LOG` governs log signals (stdout JSON + OTLP logs); `OTEL_TRACES_FILTER` (default `info`) governs the spans-as-traces layer. Do **not** collapse them back into a single global `EnvFilter`. Call `telemetry::install_http_layers(router)` in every service's `api/mod.rs` to mount the RED-metrics middleware + inbound `traceparent` extraction + the INFO-level `TraceLayer`.

27. **Metric label cardinality is bounded — never put unbounded identifiers on a metric label.** The RED histogram (`http.server.request.duration`, seconds, seconds-scale buckets) is labelled with the matched route **template** (via `MatchedPath`, never the raw path), method, and status code only. Domain meters (sweep counters, provisioned counter, active-tunnel gauge) carry only small enum values or no labels at all. `tenant_id`, `network_id`, `daemon_id`, slug, IP address, request-id, and any other unbounded identifier go on **traces and logs**, not metric labels. The SDK default histogram boundaries are millisecond-scale; always override to seconds-scale boundaries (e.g. `[0.005 .. 10.0]`) when recording durations in seconds.

## Test placement

Tests **must not** be inline (`mod tests { ... }` inside the source file).

Paths below are relative to the owning crate (`crates/common/`, `crates/tenants/`, `crates/ddns/`, or `crates/tunneller/`).

### Unit tests (`src/`)

Tests that access private internals or use mock/in-memory substitutes belong inside the crate:

- `src/<module>/tests.rs` — unit tests of a single module (access to private items via the child-module relationship)
- `src/repository/tests/<module>.rs` — repository-level unit tests using a live Postgres pool (still inside the crate, gated with `#[ignore = "requires Postgres (docker compose up -d)"]`)

Declare them with `#[cfg(test)] mod tests;` at the bottom of the source file.

### Integration tests (`tests/`)

Tests that exercise the public API end-to-end belong in the owning crate's `tests/` dir. They are compiled as a separate crate so they can only call `pub` items — this is intentional. Shared helpers live in `tests/common/mod.rs`.

- `crates/ddns/tests/api.rs` — DDNS HTTP API surface via mock repos
- `crates/ddns/tests/work_queue_mtls.rs` — mTLS work-queue client integration test
- `crates/tunneller/tests/api.rs` — the daemon `GET /v1/tunnel` surface (auth / network-scope / routing policy / WS upgrade) against a live mock-backed server
- `crates/tunneller/tests/mesh_mtls.rs` — inter-node forward round-trip, the forward acceptor's scope-direction rule (a chain-valid wrong-service peer is dropped by the real `serve_forward_on` loop), initiator-pin rejections, and `TenantsClient` reads — all over real mTLS (`#[ignore]`)
- `crates/tenants/tests/resource_reads.rs` — the mesh-plane `GET /v1/networks/{id}` · `GET /v1/tenants/{id}` reads
- `crates/tenants/tests/auth.rs` — the web-auth HTTP surface (WS-F): password signup/login/reset, OIDC callback + auto-link, session↔JWT exchange, `GET /v1/me`, logout

Add new integration test files here when a feature requires two or more real infrastructure components to test correctly. (The former pebble-based `tests/acme.rs` / `tests/tls_renewal.rs` were removed with the in-app TLS/ACME subsystem.)

### Cross-service end-to-end tests (`end2end-tests/`)

A test that needs **multiple real service binaries running together** (not just a live DB or a single in-process mTLS round-trip) belongs in a dedicated docker-compose scenario under `end2end-tests/<scenario>/`, mirroring the daemon repo's layout — **not** in a service crate's `tests/`. Each scenario is its own `publish = false` workspace member: a `compose.yaml`, the `#[ignore]`d test in `tests/`, and any mock fixtures. Drive it from `source/Makefile` (`make e2e-*`), generating dev mesh material with the `xtask` cert generator (`cargo run -p xtask -- gen-certs`); the per-service `crates/*/Dockerfile`s build the images.

- `end2end-tests/mesh/` — the full tombstone lifecycle over **real SPIFFE mesh mTLS**: real `tenants` + `ddns` containers (two Postgres instances, a wiremock Cloudflare) exercising provision → USER deregister → reaper → sweep. See its `README.md`. `ddns` points `CLOUDFLARE_API_BASE` at the wiremock so the harness never touches a real zone.

## SQL conventions

- Query strings are `const &str` at module level; never interpolate *runtime* values into SQL (bind them with `$N`). Where a query `format!`s only a compile-time `const` column list (e.g. `format!("SELECT {NETWORK_COLS} FROM …")`), sqlx 0.9's `SqlSafeStr` bound rejects the resulting `String`, so wrap it in `sqlx::AssertSqlSafe(format!(…))` — the deliberate, audited opt-out for safe-but-dynamic SQL (real inputs are still `$N`-bound). `AssertSqlSafe` is for SQL only; connection URLs passed to `PgPool::connect`/`db::init` take a plain `&str`, not `SqlSafeStr`.
- **PostgreSQL** stores `DateTime<Utc>` natively as `TIMESTAMPTZ` via sqlx's `chrono` feature — no `to_rfc3339()` / `.parse()` round-tripping.
- Mutations always use `self.pools.write`; reads always use `self.pools.read`.
- Postgres has no unsigned integers: store any unsigned counter as `INTEGER`/`BIGINT` and convert explicitly at the boundary (never `as`).
- Keep the Neon serverless pool rules in mind: `min_connections = 0`, graceful reconnect; do not hold an idle connection that would prevent autosuspend.

## Adding a new authenticated endpoint

1. Put its request/response DTOs in **`common::contract`** (invariant #21), and keep any
   `impl From<DomainType> for ContractDTO` in the owning service crate.
2. Give the module a `pub fn register(r: OpenApiRouter<AppState>) -> OpenApiRouter<AppState>`
   (using `utoipa_axum::routes!`), then add it to a **route group** wrapped in
   `authenticate(CallerType)` for the caller kinds it accepts — see the group wiring in each
   service's `api/mod.rs` (`from_fn_with_state(state, |st, r, n| authenticate(CallerType::DAEMON, st, r, n))`).
   A SERVICE-plane endpoint (mesh mTLS) is mounted on the mesh listener, not the public router.
3. Read the verified caller with the `AuthCaller(Caller)` extractor and match the kind you need
   (`Caller::Daemon(d)` exposes `tenant_id` + `network`); apply any **policy in the handler**,
   not in the endpoint you call.
4. Add `#[utoipa::path(...)]` with at least `401` in the responses.

## Adding a new unauthenticated endpoint

- Put it in the **bootstrap** group (no `authenticate` layer) — e.g. health, or an endpoint that
  verifies its own one-time-code / key-PoP credential in the handler.
- Annotate `#[utoipa::path]` with `security(())` to mark it public in the OpenAPI spec.

## Error handling

- `ApiError` / `ErrorBody` are the transport-neutral HTTP shape and live in `wardnet_common::error` (re-exported as `crate::error::{ApiError, ErrorBody}` in each service crate).
- Return `ApiError` from handlers — it maps to `(StatusCode, Json<ErrorBody>)` via `IntoResponse`.
- Wrap database errors with `map_err(ApiError::Internal)`.
- Use `ApiError::BadRequest`, `ApiError::Conflict`, `ApiError::TooManyRequests`, `ApiError::Unauthorized`, `ApiError::Forbidden` for client errors.
- Service-layer domain errors stay HTTP-agnostic; their `From<..> for ApiError` mappings live in each service crate's `error.rs` (the orphan rule permits them there). `TenantsError` maps in `crates/tenants/src/error.rs` and `DdnsError` maps in `crates/ddns/src/error.rs` (each crate owns the `From` for its own domain error, per the orphan rule).

## DNS provider

`DnsProvider` is a trait in `wardnet_common::dns_provider` (`upsert_a_record` / `upsert_txt_record` / `delete_record` / `find_a_record`). Production uses `CloudflareDnsProvider` (`crates/ddns/src/cloudflare/`). In tests, use the `MockDnsProvider` in `crates/ddns/src/test_helpers.rs` (it simulates a Cloudflare zone). Never call the Cloudflare REST API in unit tests. The optional `CLOUDFLARE_API_BASE` env var (`CloudflareDnsProvider::with_base_url`) overrides the API base URL so the e2e harness can point a real `ddns` binary at a wiremock; it is **unset in production** (the real API).

## Validation

All name and public-key validation goes through `wardnet_common::validation`:
- `validate_name(&str) -> Result<(), ApiError>` — structured error messages for registration
- `is_valid_name(&str) -> bool` — availability endpoint (returns `false` for invalid names, no error)
- `validate_public_key(&str) -> Result<[u8; 32], ApiError>` — verifies base64 + 32-byte length and returns the decoded key

`RESERVED_NAMES` (in the same module) is the single source of truth for reserved slugs.

## Running checks

Run from `source/` (the workspace root). All three gates must be green before a PR:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # Postgres-backed tests are #[ignore]'d unless `docker compose up -d`
```

The cloud services have no Linux-specific dependencies and build natively on macOS.

Postgres-backed `#[ignore]` tests are gated on per-service env vars — set the one(s) you need:

```sh
TENANTS_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432
DDNS_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432
TUNNELLER_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432
```

Only the env var for the crate under test is consulted; the others are harmless no-ops.

CI requires the **`All checks passed`** aggregator job (defined in `ci.yml`/`pr.yml`) — this is the single required branch-protection check; per-service leaves gate under it.

## Releasing a service

Each service has its own tag-triggered release pipeline. To cut a release for a service:

1. Bump `version` in `source/crates/<service>/Cargo.toml` and commit.
2. Tag and push: `git tag <service>-v<version> && git push origin <service>-v<version>`
   — where `<service>` is one of `tenants`, `ddns`, or `tunneller`.

The release workflow validates that the tag version matches the crate's `Cargo.toml` version and aborts if they diverge. A `workflow_dispatch` on any ref is a dry run (builds + signs, never publishes).

## Local dev

Point `DATABASE_URL` at a local/Neon dev Postgres and set the Cloudflare values (and the other secrets)
as plain env vars with dummy values (`Config::from_env` reads them the same way in every environment).
Never commit real Cloudflare tokens; in production inforge injects all secrets as env vars sourced from
Infisical (invariant #9) — see the infrastructure repo for provisioning.
