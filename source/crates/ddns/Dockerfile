# Multi-stage build for the wardnet-ddns service.
#
# Context must be the workspace root (`source/`):
#   docker build -f crates/ddns/Dockerfile .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p wardnet-ddns

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/wardnet-ddns /usr/local/bin/wardnet-ddns
ENTRYPOINT ["/usr/local/bin/wardnet-ddns"]
