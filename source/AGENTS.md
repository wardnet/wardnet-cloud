# wardnet-cloud agent guide

Conventions and invariants for agents working inside `source/`.

> **WS-C re-scope (2026-06-16):** the Tenants service was rebuilt to the end-state
> **tenant → network → daemon** model with a `provisioning_state` lifecycle, and auth
> was unified into `common::auth::authenticate(CallerType)` (`SERVICE` via mTLS /
> `DAEMON`/`USER` via JWT). PoW self-registration and the `introspect` endpoint are
> gone; DNS is now reconciled from desired state via a mesh work-queue
> (`GET/PATCH /v1/networks`). See `CONTEXT.md` (glossary) and `docs/adr/0001`,
> `docs/adr/0002`. Several invariants below still describe the *previous*
> identity/bearer model and are superseded pending the WS-J docs pass.
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

> **Status:** invariants tagged `[#444]`/`[#445]` describe the agreed target architecture (SNI/tunnel
> data plane, PostgreSQL/Neon, runtime `SecretsProvider`, multi-node `TunnelRouter`) and land with those
> issues. Everything untagged is live on `main` today.

## Workspace layout

`source/` is a Cargo workspace (`source/Cargo.toml`, `resolver = "3"`, edition 2024) with four members
(`common`, `tenants`, `ddns`, `tunneller`):

- **`crates/common`** (lib `wardnet_common`) — everything genuinely cross-service: `token`, `mtls`,
  `proxy_protocol` (incl. `client_ip`), `replay_cache`, `dns_provider`, `db` (`DbPools` / `connect`),
  `error` (`ApiError` / `ErrorBody`), `validation`, the generic `auth` core (`auth_layer<S: AuthContext>`
  — body guard, timestamp window, canonical payload, Ed25519 PoP, replay cache — each bin implements
  `AuthContext::resolve_credential`), `serve` (`run_api`, the PROXY-required plain-HTTP listener, plus a
  stream-generic `connection`), `mtls` (SPIFFE mesh mTLS: `SpiffeId`/`ExpectedPeer`, the SNI-ignoring
  `client_config_from_pem`/`mesh_client` initiator side, `server_config_from_pem` + `peer_spiffe_id`
  acceptor side, the hot-reload holders `MeshClient`/`ReloadableServerConfig`, and `watch_mesh_files`),
  generic `health::register`, the
  env-`config` helpers, and — transiently, until enrollment is redesigned — `pow`.
- **`crates/tenants`** (bin `wardnet-tenants`, lib `wardnet_tenants`) — the global identity/naming
  service, carved out of `cloud` in WS-B. Owns the identity + challenge repos, the JWT `Signer`,
  `TenantsService`, and the **global naming DB** (its `migrations/` — moved from cloud's
  `migrations-global/` — and its own `db::init` with a crate-relative `sqlx::migrate!`), plus its own
  `config`/`state`/`error`. Serves a **public** nginx-fronted router (`register`/`challenge`/`names`/
  `token`/`deregister`/`health`) with dual-path auth, **plus** a separate **internal mesh-mTLS**
  reconcile listener (`src/mesh.rs` — mTLS transport only; handlers in `src/api/reconcile.rs`,
  `GET/PATCH /v1/networks`) with no JWT layer. Account deregister (`DELETE /v1/tenants/{id}`, USER,
  owner-checked, 202, idempotent) **tombstones** (`deregistered_at`) rather than deleting: it cascades
  the tenant's networks to `deprovisioning` (the DDNS reaper does DNS teardown — invariant #19) and
  cancels the subscription, and a periodic **sweep loop** (`TENANT_SWEEP_INTERVAL_SECS`, default 3600,
  N-replica-safe) FK-cascade-deletes tombstoned tenants once their networks are gone. The email is freed
  for a fresh signup the moment the tombstone is set — a **partial unique index** (`email WHERE
  deregistered_at IS NULL`) means only live tenants reserve it, and `mint_jwt`/`enroll` reject a
  tombstoned tenant. Depends on `wardnet_common`.
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

1. **Bearer token never stored raw.** `register.rs` returns `hex(random_32_bytes)` to the caller once and stores only `hex(SHA-256(token))`. Never persist, log, or echo the raw token.

2. **Auth is a route-layer caller-type guard, not a path-gate.** Every authenticated route group is wrapped in `authenticate(CallerType)` (`common::auth`), which resolves the caller (SERVICE via mTLS / DAEMON · USER via JWT+PoP) and rejects anything outside the allowed set. There is **no `/v1/installs/` path prefix** any more — DDNS report-IP/ACME and the Tunneller `GET /v1/tunnel` are all route-layer `authenticate(DAEMON)`, scoped to the JWT `net` claim, so a daemon can only ever touch its own network. (The legacy `auth_layer` opaque-bearer path-gate is retired with the old `cloud` bin; only Tenants ever held an identity table, and that path is gone.)

3. **Uniqueness before challenge burn.** In `register.rs`, the global `names().reserve()` (the atomic slug allocation — its unique violation is the name-clash guard) always runs _before_ `challenges().consume()`. Reversing the order would consume the user's PoW proof on a name-conflict error. Registration is a **two-database saga** (global `names` + regional `installs`); any failure after `reserve` must `release` both rows.

4. **ReplayCache keyed on `{install_id}:{timestamp}:{body_hash}`.** Do not change this format without updating the replay window constant and tests. The window is ±120 s (double the timestamp window) for clock-skew at the cache boundary.

5. **Body buffered before auth.** The 1 MiB body guard runs for _every_ request, including unauthenticated ones. It is the first thing `auth_layer` does — before any DB call.

6. **`pub_key_bytes` decoded once.** The install row decodes the base64 public key into `[u8; 32]` when loaded from the DB. Auth uses `install.pub_key_bytes` directly — never re-decode the base64 string on a hot path.

7. **Canonical payload includes `path_and_query`.** The Ed25519 signature covers `"METHOD\npath_and_query\ntimestamp\nhex-sha256(body)"`. Use `uri.path_and_query()`, not just `uri.path()`, so query parameters are authenticated.

8. **X-Forwarded-For only from loopback peers.** `client_ip()` (in `wardnet_common::proxy_protocol`) trusts the header only when `addr.ip().is_loopback()`. Never call `headers.get("X-Forwarded-For")` directly in a handler. The real peer address comes from the PROXY v1 header threaded in as `ConnectInfo` (see #13), not from the kernel socket.

9. **Secrets come from `SecretsProvider`, never the environment.** `[#445]` In production, `DATABASE_URL`, the Cloudflare token, etc. are fetched at runtime into memory via the `SecretsProvider` trait. Never read prod secrets from env, never write them to disk, never log them. The bootstrap session token lives on tmpfs only. `FileSecrets`/`EnvSecrets` are for dev/test with dummy values only.

10. **(retired)** The old per-install **nonce challenge** for the tunnel upgrade is gone. `GET /v1/tunnel` is route-layer `authenticate(DAEMON)`: the per-request Ed25519 **PoP** that the auth layer enforces on the upgrade GET already proves possession of the daemon's `cnf` key, so a separate server-nonce challenge is redundant. The `into_parts`/`from_parts` in the middleware preserve the `OnUpgrade` extension, so the WebSocket upgrade survives the layer (proven by `tunneller/tests/api.rs`).

11. **Route inbound streams only through `TunnelRouter` (LIVE).** The SNI demuxer (`tunneller/src/sni`) hands every stream to the `TunnelRouter` trait keyed on **vanity slug** — never look up the in-memory `TunnelRegistry` `DashMap` directly outside `LocalRouter`. `LocalRouter` short-circuits slugs this node owns into the registry and forwards everything else over the private inter-node mesh link to the `node_addr` in `tunnel_routes`. A node `upsert`s its ownership on tunnel connect and deletes it on disconnect (own-node-guarded). The table is a **hint**: each node's live registry is the source of truth, so a forward to a node whose registry no longer holds the slug **fails closed** (the connection is dropped, not mis-routed). See `docs/adr/0004`.

12. **The tunnel registry is in-memory and per-node (LIVE).** It is not persisted; after a node restart all daemons reconnect. Registration is keyed on slug with a per-tunnel **abort token** (`CancellationToken`) + a generation so a reconnect cleanly displaces a stale handler and a superseded handler's cleanup is a no-op. The inter-node `forward` listener is **private mesh-mTLS only** (it bypasses SNI, so it must be authenticated — the handshake *is* the auth); a peer reads a `{slug, dest_port}` preamble then splices the raw L4 stream into the local registry. Treat `conn_id` as wrapping (`u32`). A live tunnel is torn down by the **pull-reconcile abort reaper** (per-node, ADR-0004) when its network is `404`/`deprovisioning` or its subscription lapses; the same pass heartbeats `last_seen`, and a TTL reaper purges rows orphaned by a crashed node.

> ⚠️ **Superseded by WS-A (invariants #14–#17 below):** the in-app TLS-termination + ACME
> subsystem has been **removed** (`tls/`, `acme/`, `sweep/`, `http01.rs`, `crypto.rs`,
> `repository/tls.rs`, the `bridge_tls` migration, `ENCRYPTION_KEY`, and the SNI terminate
> branch are all gone). Public TLS is now fronted by an inforge-injected **nginx sidecar**
> (which also runs ACME). The control-plane API is served as **plain HTTP** behind it
> (#13, #14 below), and the tenant data plane is pure **L4 SNI passthrough** — Tunneller
> never terminates. Invariants **#15–#17 describe deleted machinery** and survive only as a
> historical record until the WS-J rewrite; do not treat them as live. #14 has been
> **replaced** with the plain-HTTP rule below.

13. **Strip the PROXY v1 header first, consuming exactly the line.** Every public listener is fronted by nginx with PROXY protocol v1. Read the header byte-by-byte up to its CRLF and **no further** (`proxy_protocol::read_required`/`read_optional`) — never a `BufReader`, which would swallow the `ClientHello` and break the SNI peek. The recovered client IP must be threaded into the API as `ConnectInfo` so the per-IP rate limiter and IP-bound PoW keep working. On the API listener the header is **required** and **fail-closed**: a connection with a missing/invalid header, a read timeout, or a `PROXY UNKNOWN` family is **dropped** rather than served against nginx's loopback address (which would let `client_ip()` trust a spoofable `X-Forwarded-For`). See `serve::run_api` in `crates/common/src/serve.rs` (used by every service's `main.rs`).

14. **The control-plane API is served over plain HTTP behind nginx.** It listens on `config.api_listen_addr` (public `:80`, fronted by nginx which terminates TLS) and serves `/v1/health` + the API. There is no in-process TLS for the API any more — do **not** add a rustls/TLS-terminating branch to the API listener. The SNI listeners (`https_listen_addr`/`dot_listen_addr`) are **passthrough-only**: `sni::run(...)` forwards to the tenant tunnel on `dest_port` 443 / 853 and never inspects or terminates the inner TLS.

15. *(superseded — deleted machinery)* Cert/account material was AES-256-GCM-sealed under `ENCRYPTION_KEY` before touching `bridge_tls`. All of `crypto.rs`, the `bridge_tls` table, and `ENCRYPTION_KEY` have been removed.

16. *(superseded — deleted machinery)* ACME issuance was coordinated by the `bridge_tls_lease` winner with version-based hot-swap. nginx now owns ACME; the lease/sweep/`acme_http_challenge` machinery is gone.

17. *(superseded — deleted machinery)* The public `GET /.well-known/acme-challenge/{token}` responder has been removed; nginx answers HTTP-01.

18. **Two auth planes: JWT for external daemons, mTLS for the mesh.** External daemon/user requests (via nginx) authenticate with an identity JWT (Tenants-signed, verified offline) plus, for daemons, the Ed25519 PoP — all via route-layer `authenticate(DAEMON|USER)`. **Inter-service / mesh-plane calls carry no JWT** — they authenticate by **SPIFFE-verified** mutual TLS: a client cert chained to the per-scope **trust bundle** whose URI SAN parses to a `ServiceIdentity{trust_domain,env,scope,service}` that `authenticate(SERVICE)` accepts. Mesh leaves carry a SPIFFE URI SAN only (**no DNS SAN**), so initiators pin an `ExpectedPeer{service,scope}` in a custom verifier that **ignores the SNI** (`mtls::client_config_from_pem`/`mesh_client`), and acceptors enforce a **scope-direction rule** on the parsed peer id (global acceptor → any in-bundle scope; regional acceptor → peer scope == own scope) instead of a per-peer-service allowlist (the bundle is the allowlist). Rotated material hot-reloads in place (ADR-0005). The **Tunneller spans both**: it is a JWT-only daemon endpoint (`GET /v1/tunnel`) *and* a mesh-mTLS client (its routing policy reads Tenants' `GET /v1/networks/{id}` · `GET /v1/tenants/{id}`, and its nodes forward to each other over a private mesh-mTLS link whose acceptor additionally pins `service == tunneller`). The `aud` claim was deliberately **not** added — grant scoping is deferred to WS-F.

19. **The mesh work-queue is mTLS-only and off the public router.** The reconcile work-queue (`GET/PATCH /v1/networks`, Tenants ↔ DDNS provisioner/reaper) is served by a separate internal listener on `config.mesh_listen_addr`. **Transport vs API are split:** the mTLS listener lives in `crates/tenants/src/mesh.rs` (`serve_mesh` — TLS acceptor + accept loop + semaphore), and the SERVICE-plane handlers + DTOs live in `crates/tenants/src/api/reconcile.rs` (`pub fn router`). "mesh" names the mTLS *transport*, never a route group. The reconcile router is **not** mounted on the public nginx-fronted router and carries `authenticate(SERVICE)` — the mutual-TLS handshake (server presents the mesh leaf via the hot-reloadable `mtls::ReloadableServerConfig`, requires a client cert chained to the trust bundle via `mtls::server_config_from_pem`; the accept loop then parses the peer's SPIFFE id with `mtls::peer_spiffe_id` and stamps the structured `ServiceIdentity`, applying the global-acceptor scope rule) is what `SERVICE` resolves against. Never expose the reconcile routes on the public router or add a JWT/bearer layer to them. (`POST /v1/introspect` is gone — DNS teardown is the DDNS reaper draining this work-queue, per ADR-0001.)

20. **DDNS A-record creation is the provisioner's alone, and is adopt-or-create + CAS.** Only `DdnsService::provision` (the provisioner) creates a Cloudflare A record; **report-IP only ever updates in place** (`OperationalRepository::record_ip` writes the `ip` column only — never `fqdn`/`cf_a_record_id`), so a daemon's IP report can never resurrect a record the reaper just deleted. To tolerate N regional replicas, `provision` adopts an existing record for the FQDN or creates one, then CAS-claims the id (`WHERE cf_a_record_id IS NULL`); on a lost CAS it deletes its record **only if** that record is not the one the winner stored. Do not add a create path to report-IP, and do not drop the `cf_a_record_id IS NULL` guard on the claim. See ADR-0003.

21. **Every API request/response DTO lives in `wardnet_common::contract`, shared by producer and consumer.** A DTO defined in the producing service and re-declared (a "deserialize twin") in the consumer drifts silently; instead both crates depend on the one type in `common::contract`, so a producer change is a compile error on the consumer (`ErrorBody` is the original precedent). This covers the whole wire surface — bootstrap/daemon/account/mesh DTOs alike — including the embedded value objects (`ProvisioningState`, `SubscriptionStatus`, `Entitlement`), which also double as Tenants' DB-domain enums (their `as_str`/`from_db` helpers live on the contract type). A resource view (`NetworkView`/`TenantView`/`DaemonView`) is the **full** resource, never trimmed to one caller's current needs; tolerant consumers read only the fields they use. The `impl From<DomainType> for ContractDTO` conversion stays in the owning service crate (orphan-rule-legal, since the domain type is local). Do **not** add a second copy of a DTO in a service crate, and do not narrow a view to a caller.

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
- `crates/tunneller/tests/mesh_mtls.rs` — inter-node forward round-trip + `TenantsClient` reads over real mTLS (`#[ignore]`)
- `crates/tenants/tests/resource_reads.rs` — the mesh-plane `GET /v1/networks/{id}` · `GET /v1/tenants/{id}` reads

Add new integration test files here when a feature requires two or more real infrastructure components to test correctly. (The former pebble-based `tests/acme.rs` / `tests/tls_renewal.rs` were removed with the in-app TLS/ACME subsystem.)

## SQL conventions

- Query strings are `const &str` at module level — never inline in `sqlx::query(format!(...))`.
- **PostgreSQL** `[#444/#445]` stores `DateTime<Utc>` natively as `TIMESTAMPTZ` via sqlx's `chrono` feature — no `to_rfc3339()` / `.parse()` round-tripping.
- Mutations always use `self.pools.write`; reads always use `self.pools.read`.
- Postgres has no unsigned integers: store counters like `difficulty` as `INTEGER`/`BIGINT` and convert explicitly at the boundary (never `as`).
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

`DnsProvider` is a trait in `wardnet_common::dns_provider` (`upsert_a_record` / `upsert_txt_record` / `delete_record` / `find_a_record`). Production uses `CloudflareDnsProvider` (`crates/ddns/src/cloudflare/`). In tests, use the `MockDnsProvider` in `crates/ddns/src/test_helpers.rs` (it simulates a Cloudflare zone). Never call the Cloudflare REST API in unit tests.

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

## Local dev

Point `DATABASE_URL` at a local/Neon dev Postgres and use `FileSecrets`/env for the Cloudflare values
(dummy in tests). Never commit real Cloudflare tokens; in production secrets are resolved at runtime via
the `SecretsProvider` (Infisical) — see the infrastructure repo for provisioning.
