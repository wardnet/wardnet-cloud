# Mesh-mTLS end-to-end harness

A docker-compose topology that exercises the WS-E **SPIFFE mesh mTLS** plane with
real service binaries — no mocks on the mesh path. It stands up:

- **`tenants`** — the global identity service (serves the mesh-mTLS work-queue +
  the control-plane API), backed by **`pg-global`**.
- **`ddns`** — the regional reconciler (provisioner + reaper) that drains the
  Tenants work-queue *over mesh mTLS* as a client, backed by **`pg-regional`**.
- **`cloudflare`** — a [wiremock](https://wiremock.org/) standing in for the
  Cloudflare v4 API, so the harness never touches a real zone. `ddns` is pointed at
  it via the `CLOUDFLARE_API_BASE` override.

The mesh leaves (SPIFFE URI SAN only, no DNS SAN), the trust bundle, and a dev JWT
keypair are minted by the `xtask` cert generator and mounted read-only at the
`MTLS_*_PATH` / `JWT_*_KEY_PATH` locations.

## What the test proves

`tests/tombstone_flow.rs` drives the full account-closing lifecycle end to end:

1. The **provisioner** lists `provisioning` networks over the SPIFFE-verified mesh,
   publishes the A record (to wiremock), and transitions the network to `active` —
   proving the handshake + `GET`/`PATCH /v1/networks` round-trip between two real
   binaries with `xtask`-minted leaves.
2. A **USER `DELETE /v1/tenants/{id}`** tombstones the account and cascades its
   networks to `deprovisioning`.
3. The **reaper** tears the record down and reports `deprovisioned` (deleting the
   network row), then the Tenants **sweep** deletes the now-network-less tombstone.

Tenant/network and operational-IP state are seeded directly via SQL; the daemon
enrollment flow is covered by the unit/api tests, not here. The single `DELETE`
is issued over a raw socket with a PROXY v1 preamble (the API listener requires
one — invariant #13).

## Running it

From `source/`:

```sh
make e2e-all      # gen certs → build images → up → run test → tear down (always)
```

Or step by step (useful when iterating):

```sh
make e2e-up       # gen certs + compose up -d --build
make e2e-test     # cargo test -p wardnet-e2e-mesh -- --ignored
make e2e-down     # compose down -v
```

### Container engine

Any Docker-compatible CLI works. With **Podman** (macOS), point compose at the
Podman socket first:

```sh
export DOCKER_HOST="unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')"
```

## Layout

| Path                         | What                                              |
| ---------------------------- | ------------------------------------------------- |
| `compose.yaml`               | the topology                                      |
| `wiremock/mappings/`         | mock Cloudflare v4 API responses                  |
| `tests/tombstone_flow.rs`    | the `#[ignore]`d e2e test                         |
| `certs/`                     | generated dev material (git-ignored)              |

Service Dockerfiles live next to each crate (`crates/{tenants,ddns,tunneller}/Dockerfile`).
