# wardnet-cloud — Rust workspace

This is the Cargo workspace for the wardnet-cloud services. For the project
overview, the service map, secrets handling, and the release flow, see the
[repository README](../README.md). For the architecture, invariants, and
conventions you must follow when changing code here, read **[`AGENTS.md`](AGENTS.md)**;
the domain glossary is in **[`CONTEXT.md`](CONTEXT.md)**.

## Layout

A `resolver = "3"`, edition-2024 workspace ([`Cargo.toml`](Cargo.toml)) with six
members:

| Member | Kind | Purpose |
|---|---|---|
| `crates/common` | lib `wardnet_common` | Cross-service primitives: the JWT/PoP auth core, SPIFFE mesh mTLS, the `contract` wire DTOs, `db` pools, the `event` bus, and the env-`config` helpers. |
| `crates/tenants` | bin `wardnet-tenants` | Global identity/naming service + billing + the human web-login plane. |
| `crates/ddns` | bin `wardnet-ddns` | Regional Cloudflare DNS reconciler. |
| `crates/tunneller` | bin `wardnet-tunneller` | Regional multi-node SNI-passthrough reverse-tunnel edge. |
| `xtask` | bin (dev) | Dev tooling — the `gen-certs` mesh-mTLS cert generator. |
| `end2end-tests/mesh` | test member | The docker-compose mesh-mTLS e2e scenario. |

Shared dependencies and lints are declared once at the workspace root: add deps
via `[workspace.dependencies]` and reference them with `<dep>.workspace = true`;
lints come from `[workspace.lints.clippy]` via `[lints] workspace = true`.

## Checks

Run from this directory (the workspace root). All three gates must be green
before a PR:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # Postgres-gated tests are #[ignore]'d
```

Postgres-backed repository tests are `#[ignore]`'d and read a per-service
`*_TEST_DATABASE_URL` (`TENANTS_TEST_DATABASE_URL`, `DDNS_TEST_DATABASE_URL`,
`TUNNELLER_TEST_DATABASE_URL`, default `postgres://postgres:postgres@127.0.0.1:5432`).
Start Postgres (`docker compose up -d`) and add `-- --include-ignored`.

The `Makefile` wraps these (`make check`) and drives the mesh e2e harness
(`make e2e-all` / `make e2e-test`); see
[`end2end-tests/mesh/README.md`](end2end-tests/mesh/README.md).

## Configuration

Each service loads all configuration from the environment at startup
(`Config::from_env`). In production [inforge](https://github.com/wardnet/wardnet-infrastructure)
injects the `INFORGE_DEPLOYMENT_*` identity, the loopback listen addresses, and
all secrets as environment variables (sourced from Infisical); secret *material*
(JWT + mesh PEM keys) is projected onto tmpfs with only the path passed in the
environment. Use dummy values in dev/test; never commit or log a real secret.
