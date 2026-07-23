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
