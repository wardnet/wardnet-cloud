# wardnet-cloud

[![CI](https://github.com/wardnet/wardnet-cloud/actions/workflows/ci.yml/badge.svg)](https://github.com/wardnet/wardnet-cloud/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/wardnet/wardnet-cloud/branch/main/graph/badge.svg)](https://codecov.io/gh/wardnet/wardnet-cloud)
[![Rust](https://img.shields.io/badge/rust-1.96-orange.svg)](https://www.rust-lang.org)
[![Security Audit](https://github.com/wardnet/wardnet-cloud/actions/workflows/security.yml/badge.svg)](https://github.com/wardnet/wardnet-cloud/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/wardnet/wardnet-cloud/badge)](https://securityscorecards.dev/viewer/?uri=github.com/wardnet/wardnet-cloud)
[![Dependabot](https://badgen.net/github/dependabot/wardnet/wardnet-cloud)](https://github.com/wardnet/wardnet-cloud/pulls?q=is%3Apr+author%3Aapp%2Fdependabot)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

The premium cloud platform for [Wardnet](https://github.com/wardnet/wardnet):
managed DNS, daemon enrollment, and reverse-tunnel connectivity for self-hosted
deployments, plus the account/billing layer that gates them. Registering a
daemon here is opting into paid DDNS + Tunneller; free/BYO-domain users never
touch this infrastructure.

The Rust workspace lives under [`source/`](source/). See
[`source/AGENTS.md`](source/AGENTS.md) for the architecture, invariants, and
conventions, and [`source/CONTEXT.md`](source/CONTEXT.md) for the domain
glossary.

## Services

`wardnet-cloud` is **three independently-releasable services** over a shared
`common` library, not one cloud binary:

| Service | Crate | Scope | Role |
|---|---|---|---|
| **Tenants** | `crates/tenants` | Global | Identity & naming authority — tenants, networks, daemon enrollment, subscriptions/billing (Stripe), the human web-login plane, and the JWT signer. Serves a public API + an internal mesh-mTLS reconcile work-queue. |
| **DDNS** | `crates/ddns` | Regional | Stateless DNS reconciler — drains Tenants' work-queue over mesh mTLS and drives Cloudflare toward desired state; daemon-facing report-IP + ACME endpoints. |
| **Tunneller** | `crates/tunneller` | Regional | Multi-node SNI-passthrough reverse-tunnel edge — daemons hold a WebSocket and the node forwards inbound L4 TLS down it. |

`crates/common` (lib `wardnet_common`) holds everything genuinely cross-service:
the JWT/PoP auth core, SPIFFE mesh mTLS, the wire contract DTOs, the DB pools,
the in-process domain-event bus, and the env-config helpers.

## Two authentication planes

- **JWT (external daemons & users)** — Tenants signs identity JWTs carrying an
  `aud` grant claim each service validates against its own name; daemons add an
  Ed25519 proof-of-possession. Humans authenticate via a revocable session
  cookie exchanged for a short-lived `USER` JWT.
- **SPIFFE mesh mTLS (inter-service)** — mesh calls carry no JWT; they
  authenticate by a client cert chained to a per-scope trust bundle, with
  rotated material hot-reloaded in place.

See [ADR-0002](source/docs/adr/0002-unified-caller-type-auth.md),
[ADR-0005](source/docs/adr/0005-spiffe-mesh-mtls.md),
[ADR-0008](source/docs/adr/0008-jwt-audience-grant-scoping.md), and
[ADR-0009](source/docs/adr/0009-human-web-authentication.md).

## Configuration & secrets

Each service reads **all** configuration from the process environment at startup
(`Config::from_env`). In production, [inforge](https://github.com/wardnet/wardnet-infrastructure)
injects the deployment identity (`INFORGE_DEPLOYMENT_*`), the loopback listen
addresses, and the secrets — the database DSN, the Cloudflare token, Stripe /
Resend keys, OAuth client secrets — as **environment variables**, sourcing them
from Infisical. Secret *material* (the JWT + mesh PEM keys) is projected onto
tmpfs with only the file **path** passed in the environment
(`*_KEY_PATH` / `*_BUNDLE_PATH`); the material itself never appears in an env
var. Dev/test use dummy values. Never log or persist a resolved secret.

## Building and testing

The services have no Linux-specific dependencies and build natively on macOS.
Run the three gates from `source/` (the workspace root):

```sh
cd source
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace        # Postgres-gated tests are #[ignore]'d
```

Postgres-backed repository tests are `#[ignore]`'d unless a server is reachable;
each service reads its own `*_TEST_DATABASE_URL` (`TENANTS_TEST_DATABASE_URL`,
`DDNS_TEST_DATABASE_URL`, `TUNNELLER_TEST_DATABASE_URL`) and creates a fresh
per-test database. Run `docker compose up -d` (or point the URL at a dev
Postgres) and add `-- --include-ignored`.

### Cross-service end-to-end harness

```sh
cd source
make e2e-all     # gen certs (xtask) → build images → up → run test → tear down
```

Brings up real `tenants` + `ddns` containers over SPIFFE mesh mTLS with two
Postgres instances and a wiremock Cloudflare, exercising the full account
tombstone lifecycle. See
[`source/end2end-tests/mesh/README.md`](source/end2end-tests/mesh/README.md).
With Podman, point compose at the Podman socket first (`export DOCKER_HOST=...`).

## Releasing

Each service releases **independently**, on its own SemVer tag whose version
must equal the `version` in that crate's `Cargo.toml`:

| Service | Tag prefix |
|---|---|
| Tenants | `tenants-v*` |
| DDNS | `ddns-v*` |
| Tunneller | `tunneller-v*` |

```sh
# Bump source/crates/<service>/Cargo.toml `version`, commit, then:
git tag tenants-v0.1.1
git push origin tenants-v0.1.1
```

Pushing the tag runs the matching `release-<service>.yml` caller, which drives
the shared `release-service.yml` pipeline: build the aarch64 binary, repack it
with the inforge `run` entrypoint, minisign-sign it (+ `.sha256`, SLSA
provenance), publish a GitHub Release, then dispatch the inforge raw-service
deploy on `wardnet-infrastructure` and block on it. A `workflow_dispatch` on a
non-tag ref is a dry run (build + sign, no publish/deploy).

## CI

Pushes and PRs run a path-gated pipeline: a `detect-changes` preflight gates
per-service `build-<service>` leaves (lint + test + aarch64 build), the mesh
e2e harness, and coverage, behind a single `All checks passed` aggregator. CodeQL
(Rust + Actions), `cargo audit`, OpenSSF Scorecard, dependency review, and
Dependabot round out the supply-chain hygiene.

## License

[MIT](LICENSE)
