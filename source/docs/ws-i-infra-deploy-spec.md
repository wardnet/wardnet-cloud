# WS-I — `wardnet-infrastructure` deploy spec

This is the **infra-side** checklist that lands the three cloud services as
inforge **raw services**. It is a spec, not a PR — implement it on
`wardnet/wardnet-infrastructure`. Host / region / target values are left
**blank** (`<…>`) for the maintainer to fill from the live fleet.

The cloud side (this repo) is already done: pushing a `tenants-v*` / `ddns-v*` /
`tunneller-v*` tag publishes a signed GitHub Release and then
`deploy-service.yml` fires a `repository_dispatch` at this repo:

```
event_type     = deploy-raw-service
client_payload = { service, environment: "prd", sha, artifact_url }
                   service ∈ { tenants, ddns, tunneller }
                   artifact_url = the …-aarch64.tar.gz release asset URL
```

The release tarball's root holds an executable `run` (the inforge entrypoint)
plus the single `wardnet-<service>` binary. `run` execs the binary, which reads
**all** configuration from the environment (`Config::from_env`).

## 0. Prerequisite — `deploy-raw-service.yml` must accept these services

`deploy-raw-service.yml` already accepts `repository_dispatch [deploy-raw-service]`
+ `workflow_dispatch` with inputs `service / environment / sha / artifact_url /
dry_run`, and runs `inforge releases push|deploy prd --service <s> --sha <sha>
--deploy-dir ./deployments`. Confirm `<service>` is **not** allow-listed to
`bridge` only; if it is, extend the allow-list to `tenants`, `ddns`,
`tunneller`.

## 1. `deployments/` — one raw-service config per service

`deployments/` currently has `bridge.yaml` + `inforge.yaml` (`services:
[bridge]`). Add three files modeled on `bridge.yaml`. The cloud services deploy
as **raw services** (the ADR-0026 "app" deploy path is schema-only / not
realized).

### `deployments/tenants.yaml` — **global** (one logical deployment)

- Scope: **global** — a single deployment (the global identity/naming authority),
  not regional fan-out. Target host(s): `<tenants-host(s)>`.
- Public API fronted by the nginx sidecar (PROXY protocol v1) on `:80` →
  `API_LISTEN_ADDR` (default `0.0.0.0:80`). Mesh-mTLS reconcile listener on
  `MESH_LISTEN_ADDR` (default `0.0.0.0:9443`), reachable by the regional `ddns`
  + `tunneller` services.
- Secret **material** projected onto tmpfs (path-in-env): the JWT signing key
  (`JWT_SIGNING_KEY_PATH`) + verify key (`JWT_VERIFY_KEY_PATH`), and the mesh
  leaf cert/key + trust bundle (`MTLS_LEAF_CERT_PATH` / `MTLS_LEAF_KEY_PATH` /
  `MTLS_TRUST_BUNDLE_PATH`).
- Env vars to inject (secrets from Infisical, the rest as plain config):

  | Var | Req | Notes |
  |---|---|---|
  | `GLOBAL_DATABASE_URL` | ✓ | DSN for the global naming Postgres (Neon). **secret** |
  | `INFORGE_DEPLOYMENT_REGION_SLUG` | ✓ | injected by inforge bootstrap |
  | `KNOWN_REGIONS` | ✓ | comma-separated region slugs, e.g. `<use1,euw1,…>` |
  | `JWT_SIGNING_KEY_PATH` / `JWT_VERIFY_KEY_PATH` | ✓ | tmpfs paths to the EdDSA PKCS#8 / SPKI PEMs. **material** |
  | `MTLS_TRUST_BUNDLE_PATH` / `MTLS_LEAF_CERT_PATH` / `MTLS_LEAF_KEY_PATH` | ✓ | tmpfs paths. **material** |
  | `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` | ✓ | **secret** |
  | `ACCOUNT_BASE_URL` | ✓ | the My-Account SPA origin, e.g. `<https://account.…>` |
  | `COOKIE_KEY` | ✓ | **≥ 64 bytes** (validated at startup). **secret** |
  | `API_LISTEN_ADDR` / `MESH_LISTEN_ADDR` | — | defaults `0.0.0.0:80` / `0.0.0.0:9443` |
  | `RESEND_API_KEY` / `EMAIL_FROM` | — | enrollment-code email (no-op if unset). **secret** |
  | `OAUTH_REDIRECT_BASE` | — | base for OAuth callbacks |
  | `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | — | Google OIDC. **secret** |
  | `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | — | GitHub OAuth2. **secret** |
  | `TENANT_SWEEP_INTERVAL_SECS` | — | default 3600 |
  | `TRIAL_DAYS` / `TRIAL_GRACE_DAYS` / `PAYMENT_GRACE_DAYS` / `SUB_REAPER_INTERVAL_SECS` / `USER_JWT_TTL_SECS` | — | billing/JWT tunables |

### `deployments/ddns.yaml` — **regional** (fan-out)

- Scope: **regional** — deploy in every region (`<regions>`); each region's
  `ddns` drains the global Tenants work-queue over mesh mTLS and drives that
  region's Cloudflare records.
- Env vars:

  | Var | Req | Notes |
  |---|---|---|
  | `DATABASE_URL` | ✓ | regional operational Postgres DSN. **secret** |
  | `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ZONE_ID` | ✓ | **secret** (token) |
  | `SUBDOMAIN_PARENT` | ✓ | e.g. `<my.wardnet.services>` |
  | `INFORGE_DEPLOYMENT_REGION_SLUG` | ✓ | inforge bootstrap |
  | `MESH_BASE_URL` | ✓ | the global Tenants mesh listener, e.g. `https://<tenants-mesh-host>:9443` |
  | `JWT_VERIFY_KEY_PATH` | ✓ | tmpfs path — verifies daemon JWTs offline. **material** |
  | `MTLS_TRUST_BUNDLE_PATH` / `MTLS_LEAF_CERT_PATH` / `MTLS_LEAF_KEY_PATH` | ✓ | tmpfs paths. **material** |
  | `API_LISTEN_ADDR` | — | default `0.0.0.0:80` (nginx-fronted) |
  | `CLOUDFLARE_API_BASE` | — | **leave unset in prod** (real Cloudflare API) |
  | `PROVISIONER_INTERVAL_SECS` / `REAPER_INTERVAL_SECS` / `REAPER_JITTER_SECS` | — | reconcile loop tunables |

### `deployments/tunneller.yaml` — **regional** (fan-out, multi-node per region)

- Scope: **regional**, and multi-node within a region (each node advertises a
  private mesh address for inter-node stream forwarding).
- Env vars:

  | Var | Req | Notes |
  |---|---|---|
  | `DATABASE_URL` | ✓ | regional Postgres DSN (`tunnel_routes`). **secret** |
  | `MESH_BASE_URL` | ✓ | global Tenants mesh listener, `https://<tenants-mesh-host>:9443` |
  | `MTLS_TRUST_BUNDLE_PATH` / `MTLS_LEAF_CERT_PATH` / `MTLS_LEAF_KEY_PATH` | ✓ | tmpfs paths. **material** |
  | `JWT_VERIFY_KEY_PATH` | ✓ | tmpfs path — verifies daemon JWTs on `GET /v1/tunnel`. **material** |
  | `FORWARD_ADVERTISE_ADDR` | ✓ | this node's private mesh addr peers forward to, e.g. `<10.x.x.x:9444>` |
  | `INFORGE_DEPLOYMENT_REGION_SLUG` | ✓ | inforge bootstrap |
  | `SUBDOMAIN_PARENT` | ✓ | e.g. `<my.wardnet.services>` |
  | `API_LISTEN_ADDR` / `HTTPS_LISTEN_ADDR` / `DOT_LISTEN_ADDR` / `FORWARD_LISTEN_ADDR` | — | loopback/listen defaults; public `:443`/`:853` reach the SNI listeners via the L4 proxy |
  | `RECONCILE_INTERVAL_SECS` / `RECONCILE_JITTER_SECS` | — | abort-reaper tunables |

> The authoritative required/optional split is each crate's `config.rs`
> `from_env` in `wardnet-cloud` — cross-check when filling values.

## 2. `inforge.yaml` — register the services

Extend the top-level `services:` list from `[bridge]` to include `tenants`,
`ddns`, `tunneller` (whatever shape inforge expects — match the `bridge` entry).

## 3. `resources/prd/service/` — host entries

Add host/target entries for each service under `resources/prd/service/`:

- `tenants` → **global**: `<tenants-host(s)>` (+ the global naming Postgres / Neon
  project, and the mesh-listener ingress reachable by every region).
- `ddns` → **regional fan-out**: one entry per region in `<regions>`, each with
  that region's host(s) + regional operational Postgres + Cloudflare zone.
- `tunneller` → **regional fan-out** (multi-node): per-region host set + the
  private inter-node mesh network for `FORWARD_ADVERTISE_ADDR` reachability +
  regional Postgres.

## 4. Mesh-mTLS / SPIFFE material

Each service needs a SPIFFE leaf (URI SAN
`spiffe://<trust_domain>/<env>/<scope>/<service>`, **no DNS SAN**) chained to the
per-scope trust bundle, projected onto tmpfs and re-projected in place on
rotation (the services file-watch + hot-reload — ADR-0005). Scopes: `tenants` is
**global**; `ddns`/`tunneller` are **regional** (acceptor scope-direction rule).
Provision these via the existing mesh-CA tooling for `<trust_domain>` / `<env>`.

## 5. Sanity gates

- `deploy-raw-service.yml` `workflow_dispatch` dry run for each service against a
  real `artifact_url` from a published release, confirming the tarball downloads,
  `run` is found, and the unit comes up.
- Confirm the cloud-side bot app (`APP_ID` / `APP_PRIVATE_KEY`) is installed on
  `wardnet-infrastructure` with `actions: read` + dispatch — `release-service.yml`'s
  `preflight-deploy` checks this before publishing.
