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

DEV_COMPOSE_FILE ?= dev-stack/compose.yaml
DEV_CERTS_DIR    ?= dev-stack/certs

# Container host autodetect: if a Docker daemon is reachable, use it as-is;
# otherwise fall back to the Podman machine socket (so `make dev-up` works on a
# Podman setup without the caller exporting DOCKER_HOST). Lazily expanded (`=`)
# so it only runs for the dev-* targets, not every make invocation.
DEV_DOCKER_HOST = $(shell docker info >/dev/null 2>&1 || podman machine inspect --format 'DOCKER_HOST=unix://{{.ConnectionInfo.PodmanSocket.Path}}' 2>/dev/null | head -1)

OPENAPI_DIR ?= docs/openapi

.PHONY: check fmt clippy test openapi check-openapi \
        e2e-certs e2e-build e2e-up e2e-test e2e-down e2e-all \
        dev-certs dev-up dev-down dev-logs dev-app dev

# ── Standard gates ──────────────────────────────────────────────────────────
check: fmt clippy test

fmt:
	cargo fmt --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

# ── OpenAPI specs (build artifact) ────────────────────────────────────────────
# Emit each service's public OpenAPI spec to docs/openapi/<service>.json via its
# `dump_openapi` bin. The committed specs are the source the docs site and the
# per-service Release assets are built from; `check-openapi` drift-gates them in CI.
#
# The service set is derived from which crates ship a `dump_openapi` bin (single
# source of truth): a new service is picked up automatically once it adds one.
# The crate dir name is the service name and its package is `wardnet-<name>`.
OPENAPI_SERVICES := $(patsubst crates/%/src/bin/dump_openapi.rs,%,$(wildcard crates/*/src/bin/dump_openapi.rs))

openapi:
	@mkdir -p $(OPENAPI_DIR)
	@for svc in $(OPENAPI_SERVICES); do \
	  echo "  dump_openapi $$svc"; \
	  cargo run -q -p wardnet-$$svc --bin dump_openapi > $(OPENAPI_DIR)/$$svc.json || exit 1; \
	done

# Regenerate the specs and fail if the committed copies are stale OR uncommitted.
# `git status --porcelain` (unlike `git diff`) also reports untracked files, so a
# brand-new service's generated-but-uncommitted spec trips the gate instead of
# passing green and failing later at release time.
check-openapi: openapi
	@if [ -n "$$(git status --porcelain -- $(OPENAPI_DIR))" ]; then \
	  echo "openapi specs are stale or uncommitted — run 'make openapi' and commit the result:"; \
	  git status --porcelain -- $(OPENAPI_DIR); \
	  exit 1; \
	fi

# ── End-to-end mesh harness ───────────────────────────────────────────────────
# Generate the dev mesh CA + per-service SPIFFE leaves + JWT keypair.
e2e-certs:
	cargo run -p xtask -- gen-certs $(CERTS_DIR)

e2e-build:
	$(COMPOSE) -f $(COMPOSE_FILE) build

# Bring the stack up (building images as needed). Generates certs first.
e2e-up: e2e-certs
	$(COMPOSE) -f $(COMPOSE_FILE) up -d --build

# Run the (ignored) e2e tests against a running stack — the tombstone flow over
# real mesh mTLS, and the OTLP observability assertions against the collector.
e2e-test:
	cargo test -p wardnet-e2e-mesh -- --ignored --nocapture

e2e-down:
	$(COMPOSE) -f $(COMPOSE_FILE) down -v

# One-shot: certs → up → test → guaranteed teardown (even on failure).
e2e-all: e2e-certs
	set -e; \
	trap '$(COMPOSE) -f $(COMPOSE_FILE) down -v' EXIT; \
	$(COMPOSE) -f $(COMPOSE_FILE) up -d --build; \
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
