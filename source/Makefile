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
# The `-f` set passed to every e2e compose call. CI layers the GHA-cache override
# on top, e.g. COMPOSE_FILES="-f end2end-tests/mesh/compose.yaml -f end2end-tests/mesh/compose.ci.yaml".
COMPOSE_FILES ?= -f $(COMPOSE_FILE)
CERTS_DIR    ?= end2end-tests/mesh/certs

DEV_COMPOSE_FILE ?= dev-stack/compose.yaml
DEV_CERTS_DIR    ?= dev-stack/certs

# Container host autodetect: if a Docker daemon is reachable, use it as-is;
# otherwise fall back to the Podman machine socket (so `make dev-up` works on a
# Podman setup without the caller exporting DOCKER_HOST). Lazily expanded (`=`)
# so it only runs for the dev-* targets, not every make invocation.
DEV_DOCKER_HOST = $(shell docker info >/dev/null 2>&1 || podman machine inspect --format 'DOCKER_HOST=unix://{{.ConnectionInfo.PodmanSocket.Path}}' 2>/dev/null | head -1)

.PHONY: check fmt clippy test e2e-certs e2e-build e2e-up e2e-test e2e-logs e2e-down e2e-all \
        dev-certs dev-up dev-down dev-logs dev-app dev

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
	$(COMPOSE) $(COMPOSE_FILES) build

# Bring the stack up and BLOCK until every service is healthy (`--wait`). The
# tenants/ddns `/v1/health` healthchecks are the readiness gate, so the test
# never starts against a still-migrating service. Generates certs first.
e2e-up: e2e-certs
	$(COMPOSE) $(COMPOSE_FILES) up -d --build --wait

# Run the (ignored) e2e tests against a running stack — the tombstone flow over
# real mesh mTLS, and the OTLP observability assertions against the collector.
e2e-test:
	cargo test -p wardnet-e2e-mesh -- --ignored --nocapture

# Dump all container logs (diagnostics on failure, before teardown drops volumes).
e2e-logs:
	$(COMPOSE) $(COMPOSE_FILES) logs --no-color --timestamps

e2e-down:
	$(COMPOSE) $(COMPOSE_FILES) down -v

# One-shot: certs → up (wait for healthy) → test → guaranteed teardown. On a
# non-zero exit, dump container logs BEFORE `down -v` wipes them (local parity
# with the CI log-artifact step).
e2e-all: e2e-certs
	set -e; \
	trap 'rc=$$?; [ $$rc -ne 0 ] && $(COMPOSE) $(COMPOSE_FILES) logs --no-color; \
	      $(COMPOSE) $(COMPOSE_FILES) down -v' EXIT; \
	$(COMPOSE) $(COMPOSE_FILES) up -d --build --wait; \
	$(MAKE) e2e-test

# ── Local dev stack for the My Account SPA ────────────────────────────────────
# Runs the real `tenants` backend (auth + OIDC + Stripe + email) so the SPA can
# be driven end-to-end instead of MSW. See `dev-stack/README.md`. Requires a
# filled `dev-stack/.env` (copy from `.env.example`).
dev-certs:
	cargo run -p xtask -- gen-certs $(DEV_CERTS_DIR)

# Bring the dev backend up (postgres + tenants + nginx PROXY sidecar). Generates
# mesh/JWT material first. Then run the SPA against it with:
#   cd account-dashboard-app && VITE_ENABLE_MSW=false yarn dev
dev-up: dev-certs
	@test -f dev-stack/.env || { echo "dev-stack/.env missing — copy dev-stack/.env.example and fill it in"; exit 1; }
	$(DEV_DOCKER_HOST) $(COMPOSE) -f $(DEV_COMPOSE_FILE) up -d --build
	# Restart the nginx stream proxy so it re-resolves the tenants upstream: if
	# `tenants` was rebuilt/recreated it gets a new container IP, and nginx caches
	# the old one at config-load — leaving every request answered with an empty
	# reply until nginx is bounced. Cheap and idempotent on a fresh bring-up.
	$(DEV_DOCKER_HOST) $(COMPOSE) -f $(DEV_COMPOSE_FILE) restart nginx

dev-down:
	$(DEV_DOCKER_HOST) $(COMPOSE) -f $(DEV_COMPOSE_FILE) down -v

dev-logs:
	$(DEV_DOCKER_HOST) $(COMPOSE) -f $(DEV_COMPOSE_FILE) logs -f tenants

# Run the SPA against the real dev backend (MSW off, /v1 → nginx:8080).
# Foreground process — Ctrl-C to stop. Requires `make dev-up` to be running.
dev-app:
	cd account-dashboard-app && VITE_ENABLE_MSW=false yarn dev

# One-shot: bring the backend up (detached), then run the SPA in the foreground.
dev: dev-up dev-app
