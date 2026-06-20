# 5. Mesh mTLS is SPIFFE-verified, bundle-anchored, and hot-reloaded

Date: 2026-06-17
Status: Accepted

## Context

The service mesh (Tenants ↔ DDNS, Tunneller ↔ Tenants, Tunneller node ↔ node) authenticates
peers with mutual TLS (ADR-0002, invariants #18/#19). The first cut was written against an
assumed PKI: **DNS-name-verified** leaves, a **single mesh root**, and material loaded **once
at boot** from `MESH_CA_PATH` / `MESH_CERT_PATH` / `MESH_KEY_PATH`.

The real deployer, **inforge**, issues a different contract:

- A leaf's only SAN is a **SPIFFE URI** — `spiffe://<trust_domain>/<env>/<scope>/<service>` —
  with **no DNS SAN**. `CN = <service>`; the leaf is valid for both client and server auth.
- Trust is a **per-scope bundle of intermediates**, not one root:
  `TrustSet(ownScope, allRegions)` always includes `global`; a regional service adds its own
  region; a global service adds all regions. A cross-region peer fails the chain automatically
  (its issuer is out of bundle).
- Files arrive as `mtls/{leaf.crt, leaf.key, bundle.crt}` via
  `MTLS_LEAF_CERT_PATH` / `MTLS_LEAF_KEY_PATH` / `MTLS_TRUST_BUNDLE_PATH`, and on renewal are
  **re-projected in place** at the same paths — the unit is **not** restarted.

Against that contract the original code was doubly broken: every mesh handshake failed the
DNS-name check (the leaves have no DNS SAN), and nothing reloaded rotated material.

## Decision

**1. A service learns its own identity from its own leaf.** At boot each service parses the
SPIFFE URI SAN of its own leaf (`mtls::own_spiffe_id`) into a `SpiffeId
{ trust_domain, env, scope, service }`. It does **not** configure its own name. The canonical
mesh service names are `tenants`, `ddns`, `tunneller` (matching the crate/bin names; inforge's
manifests are aligned to these spellings).

**2. Authorization = bundle membership + a scope-direction rule. No per-peer-service
allowlist.** The bundle is the allowlist — inforge only issues leaves to real members — so
chain validity already proves "is a mesh member". On top of that, the only topological rule:

- A **global** acceptor (Tenants' work-queue / resource-read listener) accepts **any**
  in-bundle, scope-valid peer.
- A **regional** acceptor (the Tunneller node↔node forward listener) accepts only a peer whose
  `scope == own scope`, and — because the forward plane is same-service-only — whose
  `service == tunneller`.

This never changes when a new caller is added to an existing service: zero code change in the
acceptor. Other regions are already bundle-blocked.

**3. Initiators pin their specific target's identity.** The lost DNS-name check is replaced by
an explicit `ExpectedPeer { service, scope }` the dialer pins — intrinsic to the call. DDNS and
Tunneller pin `tenants`/`global`; a Tunneller node pins `tunneller`/`<own scope>` for the
forward dial.

**4. The split: client-side pin in a custom verifier, acceptor-side authz in the accept loop.**
A dialer can name exactly one target, so the pin lives in a custom
`rustls::client::danger::ServerCertVerifier` (`SpiffeServerVerifier`): it delegates chain
validation to the bundle anchors (`verify_server_cert_signed_by_trust_anchor`), **ignores the
DNS SNI** entirely, then asserts the peer leaf's `service` + `scope` against the `ExpectedPeer`.
An acceptor serves many peers, so it keeps an ordinary `server_config_from_pem` (rustls enforces
the client-cert chain) and parses the post-handshake peer leaf in its own accept loop
(`mtls::peer_spiffe_id` → `ServiceIdentity`) to apply the scope-direction rule. `ServiceIdentity`
is now the structured `{ trust_domain, env, scope, service }`, not an opaque subject string.

**5. Hot-reload is per-consumer `ArcSwap` + one `notify` watcher per service.** No god-holder:
`MeshClient` (reqwest), `ReloadableServerConfig` (acceptor), and the Tunneller `MtlsForwarder`
(dialer connector) each hold their live TLS object in an `ArcSwap` that a connection snapshots
once. `mtls::watch_mesh_files` watches the PEM **parent directories** (robust to an atomic
inode swap), debounces a re-projection's event burst, re-reads the three files, and calls each
consumer's `reload`. A failed reload logs and leaves the previous material in place.

## Consequences

- Mesh handshakes work against real inforge certs; rotation needs no restart (paired with the
  inforge bootstrapper change to re-project in place rather than reload-or-restart the unit).
- `reqwest` cannot express "ignore SNI", so mesh clients are built with
  `.use_preconfigured_tls(rustls::ClientConfig)` carrying the custom verifier, not the
  high-level `add_root_certificate`/`identity` builder. The dial still sends a placeholder SNI
  the verifier ignores.
- New deps: `x509-parser` (parse the leaf URI SAN) and `notify` (file watch).
- A new mesh **caller** of an existing service is a zero-code change; a new mesh **service**
  (new acceptor) is the only thing that adds a scope-direction decision.
- The trust bundle's anchors are intermediates, not a single root; `RootCertStore` treats each
  bundled cert as an anchor, so a leaf signed by any bundled intermediate validates directly.
