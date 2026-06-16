# 2. Unified caller-type authentication

Date: 2026-06-16
Status: Accepted

## Context

The platform has three kinds of caller — peer services (the DDNS reconciler), wardnet
daemons, and (later) human account users — across two physical planes (a public,
nginx-fronted API and a private mesh). The earlier code wired auth per-service with a
bespoke `AuthContext::resolve_credential` and a separate, auth-less mTLS listener,
and there was no first-class notion of "which kind of caller may hit this route."

## Decision

A single `common::auth::authenticate(allowed: CallerType)` middleware backs every
API. `CallerType` is a bitflags set (`SERVICE | DAEMON | USER`); each route declares
the callers it accepts and the middleware rejects anything outside the set:

- **`SERVICE`** → mutual TLS. The mesh listener completes a handshake only for a
  client cert chained to the mesh CA, then stamps a `ServiceIdentity`; its presence
  is the proof.
- **`DAEMON` / `USER`** → a Tenants-signed JWT. The claims carry `tid` (tenant, always),
  `pt`/`sub` (principal kind + id), an optional `net` (network scope), and — for
  daemons — a `cnf` proof-of-possession key whose signature is verified per request.

Three **bootstrap endpoints** (issue signup code, enroll, issue token) sit outside the
middleware because they mint the very credentials above; they carry their own
one-time-code / key-PoP checks.

There is deliberately **no `aud` claim**: per-service grant scoping is a separate,
deferred question. Caller-type is a coarser, orthogonal authorization axis and is
sufficient for the current boundary.

## Consequences

- One auth path, uniformly applied; a route's accepted callers are declared at its
  definition and visible in one place.
- The mesh boundary is expressed in the same vocabulary (`SERVICE`) rather than as an
  ad-hoc auth-less listener.
- Adding the account/user plane later needs only a user-login flow that mints the
  same JWT with `pt=user`; no endpoint rewiring.
- The token shape supports network scoping today and `aud`-style scoping later
  without a breaking change.
