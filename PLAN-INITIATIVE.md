# Plan — wardnet-cloud: first fully-working release (premium cloud platform)

## Context

The wardnet cloud "bridge" (one Rust crate, formerly `source/cloud` in the daemon
monorepo) is moving to a dedicated, **all-Rust** repo `github.com/wardnet/wardnet-cloud`
(decision: little shared with the daemon, different release cycles, cleaner CI). The
**first release** of that repo is not just a refactor — it is the **full premium cloud
platform**: the monolith decomposed into independent services **plus** the monetization
layer (email accounts, Stripe subscriptions, entitlement, email-code daemon enrollment,
and a My Account site). It ships as **one release branch** that many sessions commit to,
merged once to `main` (this is how "multiple sessions, single PR" reconciles).

Why now: we are mid-extraction; rather than land a bare structural split and rebuild auth
later, the user wants the initial release to be the coherent premium product. The cloud is
a **premium feature** — free/BYO-domain users never touch this infrastructure; registering
a daemon here means opting into paid DDNS + Tunneller.

**Already done this session (uncommitted in the import worktree
`wardnet-cloud/feature/import-cloud-snapshot`):** clean-snapshot import of the monolith to
`source/` (single crate), the 3d work carried over (tombstone deregister + token refresh +
introspection, committed in the daemon worktree as `407bd22`/`cad926a`), and a first cut of
single-service CI (to be replaced by per-service CI in WS-I).

## Locked decisions (resolved via the challenge interview)

- **Repo layout:** Cargo workspace at `source/Cargo.toml`; members under `source/crates/<name>`.
  Plus a **separate React SPA** at `site/` (JS/TS, not in the cargo workspace).
- **Crates (4 Rust):** `common` (lib) + `tenants` `ddns` `tunneller` (bins). Each binary pulls
  only its own deps ("only the features it provides"). **No `account-site` Rust binary** — the
  My Account UI is a React SPA (below).
- **DB ownership — NO sharing:** Tenants = global Postgres (identity, accounts, subscriptions,
  entitlement, instance codes, names). DDNS = regional Postgres (operational rows only).
  Tunneller = **no database** (in-memory tunnel registry).
- **Delete the entire in-app TLS-termination + ACME subsystem** (`tls/`, `acme/`, `http01.rs`,
  `sweep/`, `repository/tls.rs`/`bridge_tls`, `crypto.rs` seal/open, `ENCRYPTION_KEY`). INFORGE
  injects an nginx sidecar that terminates public TLS + runs ACME for Tenants/DDNS/account-site;
  Tunneller is pure **L4 SNI passthrough** (connection carries the *daemon's* cert, Tunneller
  forwards encrypted bytes, never terminates) with its control API served as plain HTTP behind
  nginx. **Retires AGENTS invariants #13–#17.** `proxy_protocol.rs` stays (real client IP from nginx).
- **Inter-service auth = mesh-mTLS** (rcgen self-signed in dev, INFORGE-injected PEM in prod).
  Only Tenants(server) ↔ DDNS(client, the reaper) use it. Tunneller has no mesh peer.
- **DDNS reconcile reaper: fully ON.** Polls Tenants `POST /v1/introspect` over mTLS → deletes
  Cloudflare records + operational rows for tombstoned/absent installs.
- **Daemon auth = JWT + sender-constrained `cnf` PoP**, with **per-service `aud`**. Daemon keeps
  its device-local Ed25519 keypair (request signing). PoW self-service register is **RETIRED**.
- **Enrollment = email instance-code:** account (email) → Stripe subscription → entitlement
  (N instance slots) → an emailed **single-use instance code** authorizes a daemon to register
  its Ed25519 pubkey **bound to one DNS vanity**; reinstall = rebind a new keypair to an existing
  vanity. Instance code (enrollment credential) and Ed25519 key (request credential) are distinct.
- **Billing = Stripe** (Checkout + Customer Portal + webhooks drive entitlement). **Email = Resend.**
- **My Account site = React SPA** at `site/` (NOT Rust). Built to static assets and **pushed to a
  CDN** (not served by any Rust binary). It calls the **Tenants API** with an **account-session
  bearer token** (distinct from the daemon identity JWT). Leans on Stripe hosted pages so custom UI
  is thin (account, instance codes, vanities). The **account-management API endpoints live in
  Tenants** (the SPA's backend).
- **CI/release: independent per service** — own version per crate Cargo.toml; per-service tag
  prefixes (`tenants-v*` / `ddns-v*` / `tunneller-v*` / `account-site-v*`); `detect-changes` gates
  each build on its crate path **OR** `common/**`; reusable build/release/deploy + thin wrappers.
- **Daemon-side wiring** (send per-service JWTs, enroll via instance code) is in the **daemon repo**
  → out of this PR; a coordinated follow-up. "Fully working" here = cloud services complete +
  integration-tested; daemon enrollment exercised against mocks.

## Target architecture

```
source/                         # cargo workspace root (virtual manifest)
  crates/
    common/      (lib)          # shared: token(Verifier+Signer+claims+aud+canonical_payload),
                                 #   mtls, proxy_protocol, replay_cache, dns_provider trait,
                                 #   db(DbPools+connect), error(ApiError/ErrorBody), validation,
                                 #   auth primitives (Principal, AuthenticatedInstall, jwt layer),
                                 #   serve.rs, health, verify_pow (until enrollment redesign)
    tenants/     (bin)          # global DB; JWT Signer; accounts+billing+entitlement+instance
                                 #   codes; enrollment; deregister=tombstone; introspect.
                                 #   THREE auth contexts: daemon (JWT+PoP) + account-session
                                 #   (SPA bearer) + internal mesh (mTLS introspect). The account
                                 #   API is the SPA's backend. public router (nginx-fronted) +
                                 #   internal mTLS introspect listener
    ddns/        (bin)          # regional DB (operational); Cloudflare; ip + acme-challenge;
                                 #   JWT-only offline auth; reconcile reaper (MeshClient→Tenants)
    tunneller/   (bin)          # stateless L4 SNI passthrough + tunnel WS registry/handler;
                                 #   JWT-verify-at-connect (cnf challenge); no DB; no TLS terminate
site/                           # React SPA (My Account) — separate JS/TS app, NOT a cargo member;
                                 #   static build → CDN; calls Tenants API w/ account-session bearer
```

INFORGE nginx fronts tenants/ddns (TLS+ACME). Tunneller data plane is direct (:443/:853 SNI
passthrough); its control API (daemon tunnel WS) is nginx-fronted plain HTTP. The React SPA is
static-hosted on a CDN and is not fronted by any service.

## Identity / auth flow (target)

1. Human creates **account** (email) on account-site; **Stripe** subscription → **entitlement**
   (N instance slots, each may claim a vanity).
2. User requests an **instance code** (API on Tenants) → **Resend** emails it → single-use,
   tied to one vanity slot.
3. Daemon enrolls: presents the instance code + its Ed25519 pubkey → Tenants verifies the code
   + entitlement, binds pubkey↔vanity, returns the identity JWT(s).
4. Identity JWT claims: `iss=tenants`, `sub=install_id`, `aud=<service>`, `vanity`,
   `cnf={ed25519: pubkey}`, `iat`, short `exp`.
5. Every daemon request is Ed25519-signed (`token::canonical_request_payload`). DDNS/Tunneller
   verify **offline**: Tenants-signature + `iss` + `aud` + `exp` + `cnf` PoP (request sig vs cnf key).
6. Refresh at Tenants → fresh short-TTL JWT; tombstoned/de-entitled installs can't refresh
   (revocation completes within TTL). Suspended (entitlement lapsed) is enforced at refresh + reaper.

**Account session (humans, separate from daemon auth):** the React SPA logs a human in (email
login → **account-session bearer token**) and calls the Tenants account-management API with it.
Three distinct Tenants auth contexts: daemon (JWT + cnf PoP) · account-session (SPA bearer) ·
internal mesh (mTLS introspect). Never conflate the account-session token with the identity JWT.

## Work-streams (sequenced; one release branch on wardnet-cloud)

Structural streams (well-specified from exploration):

- **WS-A — Foundation.** Workspace manifest (`[workspace]`, `[workspace.dependencies]`,
  `[workspace.lints]`), create `crates/common`, move shared modules, **delete the TLS/ACME
  subsystem**. Compile traps to get right: `error.rs` orphan-rule `From` impls move with their
  service; `db::init*` can't go to common (`sqlx::migrate!` is a compile-time crate-relative
  path) — common gets a generic `init_with_pool`; `verify_pow`/`POW_DIFFICULTY`/`client_ip` →
  common (Tenants service imports them); `config.rs` → `SharedConfig` (common) + per-service Config.
- **WS-B — Tenants carve.** identity+challenge+names repos + `Signer` + `TenantsService` +
  public router + internal mTLS introspect listener; `migrations-global/` → `crates/tenants/`.
  Add `aud` to claims. Keep dual-path auth for now (bearer DB + JWT).
- **WS-C — DDNS carve + reaper.** operational repo + Cloudflare + `DdnsService` + JWT-only
  router + **ReconcileRunner** (add `OperationalRepository::list_all_ids`; loop: list ids →
  POST /v1/introspect via `MeshClient` → `delete_records` for inactive); `migrations/` (operational
  only) → `crates/ddns/`.
- **WS-D — Tunneller carve.** `sni/` (passthrough only — drop the terminate+serve-API branch) +
  `tunnel/` + JWT-verify-at-connect; control API plain-HTTP; no DB.
- **WS-E — Per-service main/config/state + mTLS + deregister.** Three+ `main.rs`/`Config`/`AppState`;
  wire mesh-mTLS (rcgen dev / PEM prod); make `deregister` **tombstone-only** (drop the
  `ddns().delete_records` call — the reaper replaces it). **Highest structural risk.**

Platform streams (each opens with its own design gate / mini-challenge):

- **WS-G — Accounts + Stripe + entitlement + email.** Account model (email-keyed) in Tenants
  global DB; Stripe Checkout + Customer Portal + **webhook → subscription → entitlement**;
  entitlement model (slots, vanity claims, **Suspended** mode — ties to the #609 lease); instance-code
  data model; Resend transactional email. *Gate:* plan tiers, Suspended semantics, login mechanism
  (magic-link vs code), webhook→entitlement mapping.
- **WS-F — Enrollment redesign.** Replace PoW register with **instance-code enrollment**; add
  **per-service `aud`** issuance. *Gate:* aud issuance shape — token-exchange at Tenants vs
  multi-token at enroll (watch the prior **"no OAuth"** constraint); instance-code TTL/single-use.
- **WS-H — My Account SPA (`site/`, React) + account API.** React SPA: signup, email login, Stripe
  portal redirect, instance-code generation, vanity management; static build → **CDN**. Backend =
  **account-management endpoints in Tenants**, authenticated by an **account-session bearer token**
  (issued on email login; separate from the daemon identity JWT). *Gate:* account-session token
  shape + login mechanism (magic-link vs emailed code); CDN target; SPA tooling (Vite/React).

Cross-cutting:

- **WS-I — Per-service CI/release/deploy.** `detect-changes` per crate (+`common` fans out to all);
  reusable `build-service`/`release-service`/`deploy-service` parameterized over service; thin
  per-service release wrappers + per-service tag prefixes; inforge deploy targets. (Replaces the
  interim single-service CI imported this session.) **Plus a separate `site/` pipeline:** React
  build (gated on `site/**`) → static assets → **CDN deploy** (its own tag/release cadence).
- **WS-J — Docs / ADRs / CONTEXT.** New-repo `AGENTS.md` (retire #13–#17; rewrite #1/#2 bearer→JWT,
  #10 cnf-from-claims; add aud, accounts, entitlement, enrollment). `CONTEXT.md` glossary. ADRs:
  (1) drop in-app TLS for nginx-fronted + L4 Tunneller; (2) JWT + cnf PoP + per-service aud auth;
  (3) email-account + entitlement + instance-code enrollment; (4) Stripe/Resend choices.

**Dependencies:** A → B,C,D → E. G lands in Tenants (needs B). F needs G + B. H needs G.
I built alongside, finalized once crates exist. J written incrementally, finalized last.

## Open design gates (decided at each stream's start, not now)

- Per-service `aud` issuance mechanism (token-exchange vs multi-token) vs the "no OAuth" stance.
- Entitlement plan tiers + Suspended-mode (#609 lease) semantics + Stripe webhook→entitlement map.
- Account login mechanism (magic-link vs emailed code); instance-code TTL + single-use enforcement.
- account-site SPA framework vs SSR; its session-auth model.
- rcgen dev mesh-CA generation (where/when in the boot path).

## Critical files / patterns

- `source/Cargo.toml` (new workspace) + `crates/*/Cargo.toml`.
- `src/config.rs` → `common::SharedConfig` + per-service `Config` (drop `ENCRYPTION_KEY`).
- `src/auth/middleware.rs` → common JWT layer + Tenants-only bearer branch; add `aud` check.
- `src/api/mod.rs` → three+ per-service routers (no shared one).
- `src/main.rs` / `src/db/mod.rs` → per-crate mains + per-crate `migrate!`.
- `src/service/ddns.rs` (`delete_records` reused by reaper; add `OperationalRepository::list_all_ids`).
- `src/api/deregister.rs` → tombstone-only.
- **DELETE:** `src/{tls,acme,sweep}/`, `src/http01.rs`, `src/crypto.rs`, `src/repository/tls.rs`,
  `migrations/*bridge_tls*`, and the SNI terminate branch.
- `.github/`: replace interim single-service CI with reusable per-service `build/release/deploy` +
  `detect-changes` + thin wrappers (model on the daemon repo's `*-cloud.yml` already imported).

## Verification (end-to-end, per release)

1. Per crate: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
   (+ `--include-ignored` with Postgres) green; `cargo build --workspace`.
2. mTLS handshake (rcgen dev certs): DDNS reaper → Tenants introspect succeeds; mis-rooted client rejected.
3. Auth: JWT accepted; expired/wrong-signer/tampered/wrong-`aud` rejected; **PoP** — request signed
   by a non-`cnf` key rejected even with a valid JWT.
4. Premium happy path: account signup → Stripe **test** subscription → entitlement granted →
   instance code emailed (Resend test/sandbox) → daemon enroll (mocked) → identity JWT(s) →
   publish IP (DDNS, JWT+PoP) → establish tunnel (Tunneller, cnf challenge) → deregister tombstone →
   reaper deletes Cloudflare records + operational row on next tick. Suspended sub → refresh denied.
5. CI: per-service pipelines build only on their crate (or `common`) changes; a `common` change
   fans out to all; each service tags/releases independently.
