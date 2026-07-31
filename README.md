# Chuvar

Consent-based memory management for AI agents — think **1Password meets OAuth
scopes**, applied to the personal and organisational knowledge you feed into AI
agents on demand.

Memories are broken into hierarchical, dotted **scopes** (`identity.basic`,
`projects.spritz.read`). Agents request scopes; a human approves time-boxed,
revocable, audited **grants**. Agents never write memory directly — every
proposed fact is staged as a diff and requires explicit human approval before
it commits. Exposed as an [MCP server](https://modelcontextprotocol.io) with a
companion approval UI.

**Status: early/v0.** The core write-path (scope model, staged-diff approval,
hybrid Postgres+pgvector retrieval) and the three v0 MCP tools work end to end
and are tested, but this hasn't shipped a tagged release yet, and several
pieces called out in the code (the embedding model, the scope classifier, auth
on the REST API) are explicit, documented placeholders — see `AGENTS.md` for
what's real today versus what's a known, tracked gap.

## License and how this project makes money

Chuvar is licensed under [Apache 2.0](LICENSE) — the full project, source
available, free for any use including running it yourself commercially, for
as long as this project exists. That's not a promise with an asterisk: there's
no time-limited license, no revenue-threshold clause, no separate gated
directory of "enterprise" code hiding functionality from the free version.

The plan for actually generating revenue, roughly in the order it'll likely
happen:

1. **Hosted SaaS** — a managed version for people who'd rather not run
   Postgres and an MCP server themselves.
2. **Support contracts** — for self-hosted deployments that want guaranteed
   response times.
3. **Enterprise-only features** — only once (1) or (2) surface a specific,
   real need for them. Nothing here today is being held back for a future
   paywall; it just doesn't exist yet.

None of (1)–(3) exist as code yet, deliberately — they get built when there's
an actual customer need to build them for, not speculatively ahead of it.

## Development

See [`AGENTS.md`](AGENTS.md) for the full architecture, stack, dev commands,
and coding conventions — it's written as onboarding for both human and AI
contributors and is the actual source of truth for how to work in this repo.

Quick start:

```sh
mise install                 # Go 1.26, Bun 1.3
docker compose up -d         # Postgres + pgvector, local dev only
cd backend && go run ./cmd/mcpserver   # MCP server (needs MCP_SUBJECT set)
cd frontend && bun install && bun run dev   # approval UI
```

## Enrolling the first device

Mutations that grant or extend authority — approving a grant request, creating
a grant directly, approving a staged diff, renewing a grant — require a
device-local TOTP code on top of the bearer token. A bearer token is readable
by anything with shell access to the environment holding it; the second factor
is what a compromised agent session cannot produce.

**Do this immediately after first start, and immediately after upgrading a
deployment that predates the `reviewer_totp` migration.** That migration adds
`totp_secret` as a nullable column with no backfill, so an upgraded deployment
starts with *zero* enrolled devices — and while zero devices are enrolled,
`POST /api/tokens` accepts a bearer token alone. Anything holding that token
can mint a new one and enrol it, which defeats every gate above. The API cannot
close that gap on its own: with no enrolled device, there is nothing to check a
code against. `apiserver` logs a `SECURITY` warning on every start until this is
done.

```sh
curl -X POST http://127.0.0.1:8080/api/tokens \
  -H "Authorization: Bearer $CHUVAR_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"alex-phone"}'
```

The response carries the new token plaintext (shown once) and a
`totp_enroll_uri` — scan it into an authenticator app. From then on the
enrolment gate is permanently closed: minting any further token requires a code
from an already-enrolled device.

There is no UI for this yet; it is a deliberate one-time operator action.

### If every enrolled device is lost

Recovery is a direct database action, not an API call:

```sh
docker compose exec postgres psql -U chuvar -d chuvar \
  -c "UPDATE reviewer_tokens SET totp_secret = NULL;"
```

Note the absence of a `WHERE` clause — it is deliberate. The gate counts every
row that has *ever* carried a secret, revoked rows included, so leaving
`revoked_at IS NULL` in place would clear only the active devices and leave the
count nonzero, keeping the gate shut. Clearing all of them returns the
deployment to the "no device has ever enrolled" state; active bearer tokens keep
working, and the next `POST /api/tokens` is ungated so you can enrol a fresh
device. Re-enrol immediately — the warning above applies again until you do.

This is intentionally not self-service over the API. Any API-reachable reset
would be indistinguishable from the attack it exists to prevent — an attacker
holding a stolen bearer token driving the same reset. `REVIEWER_BOOTSTRAP_TOKEN`
does not help here either: a fresh bootstrap token still faces a nonzero
ever-enrolled count and cannot mint. The recovery path assumes the operator has
database access, which suits this deployment shape (single operator, own
hardware) and would need revisiting for anything multi-tenant.
