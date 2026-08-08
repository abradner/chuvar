# Chuvar — Guiding Principles

> Auto-loaded every session. This file says *why* and *which way to lean*.
> **AGENTS.md says how to work here — read it before touching anything.**
> `docs/` is canonical for architecture and decisions (`architecture.md`,
> `capability-broker.md`, `decisions.md`); when in doubt, pointers over
> restatement.

## Purpose

**Just enough, for just long enough.** Chuvar lends what is yours — the facts
you know and the authority you hold — to agents (and eventually any third
party) under grants that are scoped, time-boxed, revocable, audited, and
attributable. Borrowed, never owned.

## Principles

1. **Grants lend; they never transfer.** Scoped, timed, revocable, audited,
   attributable — all five, or it isn't a grant.
2. **The confused agent is the adversary.** Controls defend against our own
   users' agents — misled, injected, or over-diligent. At every boundary: who
   is calling, how do we know, what happens if they lie?
3. **Zero ambient authority.** If agent context can reach a root of trust
   through a legitimate interface — an env var, a checked-in secret, an open
   port — that is a bug, not a convenience.
4. **Humans approve; agents request.** No agent-reachable path mints, extends,
   or approves authority. A bypass is never grantable; degradation is
   reported, not authorized.
5. **Fail closed, loudly.** Suspected attack ⇒ outage, never a log line.
   Missing config ⇒ no boot. No grant ⇒ block. Silence is the enemy of
   consent.
6. **Everything is attributable.** Actor identity derives from the
   authenticated credential, never the request body. Every exercise of
   authority is audited; exceptions self-report.
7. **One chokepoint per property.** Enforcement exists exactly once; any layer
   on top must pass the deletion test (removing it changes politeness, never
   possibility). Decisions are made once, dated, in `docs/decisions.md`, with
   rejected alternatives and accepted costs.
8. **Claims name their adversary — and must hold.** Interim states are stated
   ("stated, not enforced"); stopgaps record the bar they miss. An
   aspirational security comment is a bug.
9. **Centralisation obliges protection.** Chuvar concentrates exactly what a
   thief wants; at rest it must beat the scattered status quo it replaces.
   Sealed at rest is committed — never add a plaintext-content or
   plaintext-secret surface.
10. **Presence is precious.** Require the human exactly once, at grant time,
    at calm time — and make the ceremony cheap. Renewal cost sets TTL length;
    friction inflates scope. Fix the friction, never the scope.
11. **Authority is queryable; failure is legible.** An agent can ask "may I,
    and for how long?" before starting, and every denial says which kind of
    no it is.
12. **History is append-only.** Supersede, never erase: facts soft-invalidate,
    audit rows outlive revocation, the enrollment gate counts ever-enrolled.
    The past is evidence.
