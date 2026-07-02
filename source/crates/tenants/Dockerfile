# Multi-stage build for the wardnet-tenants service.
#
# Context must be the workspace root (`source/`) so the whole Cargo workspace is
# available to the build:  docker build -f crates/tenants/Dockerfile .
#
# cargo-chef splits dependency compilation (the `cook` stage) from the source
# build, so the expensive deps layer is cached and reused whenever Cargo.toml /
# Cargo.lock are unchanged — fast, and resilient to a mid-build crates.io drop
# when the layer is served from cache (GHA cache in CI, see compose.ci.yaml).
FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /src/recipe.json recipe.json
# Dependency layer — cached unless recipe.json (i.e. the manifests/lockfile) changes.
RUN cargo chef cook --release -p wardnet-tenants-bin --recipe-path recipe.json
COPY . .
RUN cargo build --release -p wardnet-tenants-bin

FROM debian:bookworm-slim AS runtime
# `curl` powers the compose /v1/health healthcheck — it must speak the PROXY v1
# preamble the API listener requires (invariant #13), via `curl --haproxy-protocol`.
# ca-certificates for outbound TLS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/wardnet-tenants /usr/local/bin/wardnet-tenants
# The migrations are embedded in the binary via sqlx::migrate!, so no copy needed.
ENTRYPOINT ["/usr/local/bin/wardnet-tenants"]
