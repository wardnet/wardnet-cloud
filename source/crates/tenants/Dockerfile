# Multi-stage build for the wardnet-tenants service.
#
# Context must be the workspace root (`source/`) so the whole Cargo workspace is
# available to the build:  docker build -f crates/tenants/Dockerfile .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p wardnet-tenants-bin

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/wardnet-tenants /usr/local/bin/wardnet-tenants
# The migrations are embedded in the binary via sqlx::migrate!, so no copy needed.
ENTRYPOINT ["/usr/local/bin/wardnet-tenants"]
