# wardnet-cloud agent guide

Conventions and invariants for agents working inside `source/`.

> **Status:** invariants tagged `[#444]`/`[#445]` describe the agreed target architecture (SNI/tunnel
> data plane, PostgreSQL/Neon, runtime `SecretsProvider`, multi-node `TunnelRouter`) and land with those
> issues. Everything untagged is live on `main` today.

## Workspace layout

`source/` is a Cargo workspace (`source/Cargo.toml`, `resolver = "3"`, edition 2024) with two members:

- **`crates/common`** (lib `wardnet_common`) — everything genuinely cross-service: `token`, `mtls`,
  `proxy_protocol` (incl. `client_ip`), `replay_cache`, `dns_provider`, `db` (`DbPools` / `connect`),
  `error` (`ApiError` / `ErrorBody`), `validation`, the generic `auth` primitives, `serve` (hyper
  connection server), generic `health::register`, the env-`config` helpers, and — transiently, until
  enrollment is redesigned — `pow`.
- **`crates/cloud`** (bin) — the temporary holding pen for all remaining service code (`api`, `auth`,
  `cloudflare`, `repository`, `service`, `sni`, `state`, `tunnel`, plus its own `config`/`db`/`error`
  shims over common). Depends on `wardnet_common`. The per-service carve into `tenants`/`ddns`/`tunneller`
  is WS-B/C/D.

**Where code goes:** if a primitive is (or will be) used by more than one service, it belongs in
`common`; service-specific logic stays in `cloud`. Shared dependencies and lints are declared once at the
workspace root — add deps via `workspace.dependencies` and reference them with `<dep>.workspace = true`;
do not pin versions per-crate. Lints come from `[workspace.lints.clippy]` (pedantic) via
`[lints] workspace = true` in each member.

## Must-know invariants (never violate these)

1. **Bearer token never stored raw.** `register.rs` returns `hex(random_32_bytes)` to the caller once and stores only `hex(SHA-256(token))`. Never persist, log, or echo the raw token.

2. **DB token lookup is path-gated.** `auth_layer` only queries the DB when the request path starts with `/v1/installs/`. Adding a new public endpoint under that prefix would silently require auth — use a different path prefix.

3. **Uniqueness before challenge burn.** In `register.rs`, the global `names().reserve()` (the atomic slug allocation — its unique violation is the name-clash guard) always runs _before_ `challenges().consume()`. Reversing the order would consume the user's PoW proof on a name-conflict error. Registration is a **two-database saga** (global `names` + regional `installs`); any failure after `reserve` must `release` both rows.

4. **ReplayCache keyed on `{install_id}:{timestamp}:{body_hash}`.** Do not change this format without updating the replay window constant and tests. The window is ±120 s (double the timestamp window) for clock-skew at the cache boundary.

5. **Body buffered before auth.** The 1 MiB body guard runs for _every_ request, including unauthenticated ones. It is the first thing `auth_layer` does — before any DB call.

6. **`pub_key_bytes` decoded once.** The install row decodes the base64 public key into `[u8; 32]` when loaded from the DB. Auth uses `install.pub_key_bytes` directly — never re-decode the base64 string on a hot path.

7. **Canonical payload includes `path_and_query`.** The Ed25519 signature covers `"METHOD\npath_and_query\ntimestamp\nhex-sha256(body)"`. Use `uri.path_and_query()`, not just `uri.path()`, so query parameters are authenticated.

8. **X-Forwarded-For only from loopback peers.** `client_ip()` (in `wardnet_common::proxy_protocol`) trusts the header only when `addr.ip().is_loopback()`. Never call `headers.get("X-Forwarded-For")` directly in a handler. The real peer address comes from the PROXY v1 header threaded in as `ConnectInfo` (see #13), not from the kernel socket.

9. **Secrets come from `SecretsProvider`, never the environment.** `[#445]` In production, `DATABASE_URL`, the Cloudflare token, etc. are fetched at runtime into memory via the `SecretsProvider` trait. Never read prod secrets from env, never write them to disk, never log them. The bootstrap session token lives on tmpfs only. `FileSecrets`/`EnvSecrets` are for dev/test with dummy values only.

10. **Tunnel upgrade requires Ed25519 challenge-response.** `[#445]` `GET /v1/installs/:id/tunnel` must verify a server-nonce challenge signed by the install's registered key before binding the tunnel — the bearer token alone is insufficient (an unauthenticated tunnel claim hijacks all of that install's traffic).

11. **Route inbound streams only through `TunnelRouter`.** `[#444/#445]` The SNI demuxer hands streams to the `TunnelRouter` trait — never look up the in-memory `TunnelRegistry` `DashMap` directly outside `LocalRouter`. Cross-node ownership lives in the `tunnel_routes` table; a node writes its ownership on tunnel connect and deletes it on disconnect.

12. **The tunnel registry is in-memory and per-node.** `[#444]` It is not persisted; after a node restart all Pis reconnect. The inter-node forward listener is **private-network-only and authenticated** (it bypasses SNI, so it must be). Treat `conn_id` as wrapping (`u32`).

> ⚠️ **Superseded by WS-A (invariants #14–#17 below):** the in-app TLS-termination + ACME
> subsystem has been **removed** (`tls/`, `acme/`, `sweep/`, `http01.rs`, `crypto.rs`,
> `repository/tls.rs`, the `bridge_tls` migration, `ENCRYPTION_KEY`, and the SNI terminate
> branch are all gone). Public TLS is now fronted by an inforge-injected **nginx sidecar**
> (which also runs ACME). The control-plane API is served as **plain HTTP** behind it
> (#13, #14 below), and the tenant data plane is pure **L4 SNI passthrough** — Tunneller
> never terminates. Invariants **#15–#17 describe deleted machinery** and survive only as a
> historical record until the WS-J rewrite; do not treat them as live. #14 has been
> **replaced** with the plain-HTTP rule below.

13. **Strip the PROXY v1 header first, consuming exactly the line.** Every public listener is fronted by nginx with PROXY protocol v1. Read the header byte-by-byte up to its CRLF and **no further** (`proxy_protocol::read_required`/`read_optional`) — never a `BufReader`, which would swallow the `ClientHello` and break the SNI peek. The recovered client IP must be threaded into the API as `ConnectInfo` so the per-IP rate limiter and IP-bound PoW keep working. On the API listener the header is **required** and **fail-closed**: a connection with a missing/invalid header, a read timeout, or a `PROXY UNKNOWN` family is **dropped** rather than served against nginx's loopback address (which would let `client_ip()` trust a spoofable `X-Forwarded-For`). See `serve_api` in `crates/cloud/src/main.rs`.

14. **The control-plane API is served over plain HTTP behind nginx.** It listens on `config.api_listen_addr` (public `:80`, fronted by nginx which terminates TLS) and serves `/v1/health` + the API. There is no in-process TLS for the API any more — do **not** add a rustls/TLS-terminating branch to the API listener. The SNI listeners (`https_listen_addr`/`dot_listen_addr`) are **passthrough-only**: `sni::run(...)` forwards to the tenant tunnel on `dest_port` 443 / 853 and never inspects or terminates the inner TLS.

15. *(superseded — deleted machinery)* Cert/account material was AES-256-GCM-sealed under `ENCRYPTION_KEY` before touching `bridge_tls`. All of `crypto.rs`, the `bridge_tls` table, and `ENCRYPTION_KEY` have been removed.

16. *(superseded — deleted machinery)* ACME issuance was coordinated by the `bridge_tls_lease` winner with version-based hot-swap. nginx now owns ACME; the lease/sweep/`acme_http_challenge` machinery is gone.

17. *(superseded — deleted machinery)* The public `GET /.well-known/acme-challenge/{token}` responder has been removed; nginx answers HTTP-01.

## Test placement

Tests **must not** be inline (`mod tests { ... }` inside the source file).

Paths below are relative to the owning crate (`crates/common/` or `crates/cloud/`).

### Unit tests (`src/`)

Tests that access private internals or use mock/in-memory substitutes belong inside the crate:

- `src/<module>/tests.rs` — unit tests of a single module (access to private items via the child-module relationship)
- `src/repository/tests/<module>.rs` — repository-level unit tests using a live Postgres pool (still inside the crate, gated with `#[ignore = "requires Postgres (docker compose up -d)"]`)

Declare them with `#[cfg(test)] mod tests;` at the bottom of the source file.

### Integration tests (`tests/`)

Tests that exercise the public API end-to-end belong in the owning crate's `tests/` dir. They are compiled as a separate crate so they can only call `pub` items — this is intentional. Shared helpers live in `tests/common/mod.rs`.

- `crates/cloud/tests/api.rs` — full HTTP API surface via mock repos

Add new integration test files here when a feature requires two or more real infrastructure components to test correctly. (The former pebble-based `tests/acme.rs` / `tests/tls_renewal.rs` were removed with the in-app TLS/ACME subsystem.)

## SQL conventions

- Query strings are `const &str` at module level — never inline in `sqlx::query(format!(...))`.
- **PostgreSQL** `[#444/#445]` stores `DateTime<Utc>` natively as `TIMESTAMPTZ` via sqlx's `chrono` feature — no `to_rfc3339()` / `.parse()` round-tripping.
- Mutations always use `self.pools.write`; reads always use `self.pools.read`.
- Postgres has no unsigned integers: store counters like `difficulty` as `INTEGER`/`BIGINT` and convert explicitly at the boundary (never `as`).
- Keep the Neon serverless pool rules in mind: `min_connections = 0`, graceful reconnect; do not hold an idle connection that would prevent autosuspend.

## Adding a new authenticated endpoint

1. Place it under `/v1/installs/` — the auth middleware enforces Ed25519 signing automatically.
2. Use the `AuthenticatedInstall` extractor to access the verified install:
   ```rust
   pub async fn my_handler(
       AuthenticatedInstall(install): AuthenticatedInstall,
       ...
   ) -> Result<..., ApiError> { ... }
   ```
3. Give the module a `pub fn register(r: OpenApiRouter<AppState>) -> OpenApiRouter<AppState>` (using `utoipa_axum::routes!`) and add a `r = <module>::register(r);` line to `build_openapi_router` in `crates/cloud/src/api/mod.rs`.
4. Add `#[utoipa::path(...)]` with at least `401` in the responses.

## Adding a new unauthenticated endpoint

- Use a path prefix **other than** `/v1/installs/`.
- Annotate `#[utoipa::path]` with `security(())` to mark it public in the OpenAPI spec.

## Error handling

- `ApiError` / `ErrorBody` are the transport-neutral HTTP shape and live in `wardnet_common::error` (re-exported as `crate::error::{ApiError, ErrorBody}` in cloud).
- Return `ApiError` from handlers — it maps to `(StatusCode, Json<ErrorBody>)` via `IntoResponse`.
- Wrap database errors with `map_err(ApiError::Internal)`.
- Use `ApiError::BadRequest`, `ApiError::Conflict`, `ApiError::TooManyRequests`, `ApiError::Unauthorized`, `ApiError::Forbidden` for client errors.
- Service-layer domain errors (`TenantsError`, `DdnsError`) stay HTTP-agnostic; their `From<..> for ApiError` mappings live in `crates/cloud/src/error.rs` (the orphan rule permits them there).

## DNS provider

`DnsProvider` is a trait in `wardnet_common::dns_provider`. Production uses `CloudflareDnsProvider` (`crates/cloud/src/cloudflare/`). In tests, implement a `MockDnsProvider` or use the existing mock in `crates/cloud/tests/api.rs`. Never call the Cloudflare REST API in unit tests.

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
