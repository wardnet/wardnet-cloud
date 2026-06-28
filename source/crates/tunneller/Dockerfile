# Multi-stage build for the wardnet-tunneller service.
#
# Context must be the workspace root (`source/`):
#   docker build -f crates/tunneller/Dockerfile .
# (Not part of the mesh e2e compose topology yet; provided for parity and future
# multi-node tunneller e2e scenarios.)
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p wardnet-tunneller-bin

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/wardnet-tunneller /usr/local/bin/wardnet-tunneller
ENTRYPOINT ["/usr/local/bin/wardnet-tunneller"]
