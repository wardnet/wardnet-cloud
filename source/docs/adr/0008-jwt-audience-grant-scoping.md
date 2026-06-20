# 8. JWT `aud` grant-scoping over the mesh service namespace

Date: 2026-06-19
Status: Accepted

## Context

Tenants-signed identity JWTs are verified **offline** by every service ([token](../../crates/common/src/token/mod.rs),
ADR-0002). Until WS-F the token carried **no `aud` claim** and verifiers ran with
`validate_aud = false`: any envelope-valid token of the right [caller type](../../CONTEXT.md)
was accepted by *any* route group of that caller type, on *any* service. A daemon token good at
the Tunneller was equally good at DDNS; a user token was good wherever `USER` was accepted.

The two existing planes already separate a lot: `SERVICE` is mesh mTLS (a different mechanism
entirely), and the caller-type guard already stops a `USER` token at a `DAEMON` route. So `aud`
adds **intra-caller-type** scoping. Its biggest concrete win is on the **bearer user token**
introduced by WS-F's web login (ADR-0009): a user JWT carries no proof-of-possession, so a
*leaked* one is replayable — scoping it tightly caps the blast radius to the one service that
should ever see it. Daemon tokens are PoP-protected, so their scoping is defence-in-depth.

The deferred question (invariant #18) was the audience **taxonomy**: what namespace `aud` draws
from, whether a token may name several audiences, and how finely a daemon token is scoped.

## Decision

**`aud` is a set of mesh service names, validated by each service against its own name.**

- **Namespace = the mesh service namespace.** `aud` values are `tenants` / `ddns` / `tunneller`
  — the *same* names a service already carries in its SPIFFE leaf
  (`ServiceIdentity.service`, ADR-0005). One identity vocabulary across both auth planes; no
  parallel "audience" namespace to invent or keep in sync.
- **`aud` is a set**, because a network-scoped daemon legitimately calls several services with
  one token. Each service's `Verifier` flips `validate_aud = true` with **its own service name**
  as the expected audience and rejects any token whose `aud` omits it. This single line retires
  "any valid token of the right caller type is accepted."
- **Scoping follows what the token is *for*** — and falls out for free, since the Tenants mint
  site already knows the token's lifecycle stage (it already decides the `net` claim):

  | Token | `aud` |
  |---|---|
  | User (web login) | `[tenants]` |
  | Daemon, tenant-scoped (pre-network, no `net`) | `[tenants]` |
  | Daemon, network-scoped (has `net`) | `[tenants, ddns, tunneller]` |

  A user token can therefore never be presented to DDNS/Tunneller; a not-yet-bound daemon token
  has no reach into the data plane it has no business in yet.

## Consequences

- The "accepted anywhere" gap closes: a token is valid only at the services it was minted for.
  Invariants **#2** (caller-type framing) and **#18** (which recorded `aud` as deferred) are
  rewritten to this reality.
- **Verifiers are configured with their own audience at boot** — `tenants` expects `tenants`,
  `ddns` expects `ddns`, `tunneller` expects `tunneller`. A misconfiguration fails closed (no
  expected audience → every token rejected), not open.
- **`aud` is set per-mint, not in the verifier**, so user (5 min, ADR-0009) and daemon (1 h)
  TTLs and audiences are independent; one signer mints both shapes.
- **Rejected alternative — per-service daemon tokens** (a distinct token per service, so a
  Tunneller token is useless at DDNS). Daemon PoP already makes a stolen daemon token unusable
  without the key, so the extra per-service token juggling buys little; the lifecycle-scoped set
  is the chosen balance.
- Adding a future service to a token's reach is a mint-site change (add its name to the set) +
  that service expecting its own name — no change to the claim shape.
