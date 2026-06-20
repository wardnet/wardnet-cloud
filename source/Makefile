# wardnet-cloud developer Makefile.
#
# The `e2e-*` targets drive the mesh-mTLS end-to-end harness under
# `end2end-tests/mesh/` (real Tenants + DDNS over SPIFFE mesh mTLS, two Postgres
# instances, and a wiremock Cloudflare). See `end2end-tests/mesh/README.md`.
#
# Container engine: any Docker-compatible CLI. With Podman, point compose at the
# Podman socket first, e.g.:
#   export DOCKER_HOST="unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')"

COMPOSE      ?= docker-compose
COMPOSE_FILE ?= end2end-tests/mesh/compose.yaml
CERTS_DIR    ?= end2end-tests/mesh/certs

.PHONY: check fmt clippy test e2e-certs e2e-build e2e-up e2e-test e2e-down e2e-all

# ── Standard gates ──────────────────────────────────────────────────────────
check: fmt clippy test

fmt:
	cargo fmt --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

# ── End-to-end mesh harness ───────────────────────────────────────────────────
# Generate the dev mesh CA + per-service SPIFFE leaves + JWT keypair.
e2e-certs:
	cargo run -p xtask -- gen-certs $(CERTS_DIR)

e2e-build:
	$(COMPOSE) -f $(COMPOSE_FILE) build

# Bring the stack up (building images as needed). Generates certs first.
e2e-up: e2e-certs
	$(COMPOSE) -f $(COMPOSE_FILE) up -d --build

# Run the (ignored) e2e test against a running stack.
e2e-test:
	cargo test -p wardnet-e2e-mesh --test tombstone_flow -- --ignored --nocapture

e2e-down:
	$(COMPOSE) -f $(COMPOSE_FILE) down -v

# One-shot: certs → up → test → guaranteed teardown (even on failure).
e2e-all: e2e-certs
	set -e; \
	trap '$(COMPOSE) -f $(COMPOSE_FILE) down -v' EXIT; \
	$(COMPOSE) -f $(COMPOSE_FILE) up -d --build; \
	$(MAKE) e2e-test
