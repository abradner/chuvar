# Chuvar — Agent Onboarding Guide

> Read this file first. It is the source of truth for AI agents working in this codebase.
> Design log / decisions: the "Brainstorm & Architecture Notes" page in the (still Memory-Vault-
> titled, not yet renamed) Notion space is the canonical design doc, not this file. This file is
> operational — how to build, run, and write code here. When the two disagree on architecture,
> Notion wins; update this file to match rather than the reverse.

## 1. What Is This?

**Chuvar** — the name has landed (Jul 2026). Earlier design docs and this repo's git history
refer to it as "Memory Vault," a working title used before the name was decided; that's historical
context, not a naming inconsistency to fix retroactively. The Notion workspace still uses the old
title pending its own rename (tracked separately).

Consent-based memory management for arbitrary agent ecosystems — "1Password meets OAuth scopes"
for personal/organisational knowledge fed into AI agents on demand. Memories are broken into
hierarchical dotted **scopes** (`identity.basic`, `projects.spritz.read`). Agents request scopes;
a human approves time-boxed, revocable, audited **grants**. Agents never write memory directly —
every proposed fact is staged as a diff and requires human approval before it commits. Exposed as
an MCP server with a companion approval UI.

**License: Apache-2.0** (decided Jul 2026) — the whole repo, unrestricted, forever; see the
README's "License and how this project makes money" section for the reasoning (Temporal/Supabase-
style: the product is opinionated enough that hosted convenience sells on its own, without needing
to hold anything back from the free version) and the actual revenue plan (hosted SaaS first,
support contracts second, enterprise-only features only once real demand names one — nothing
here is deliberately withheld from CE today). Don't scaffold a gated-directory split or a separate
private repo speculatively — that's real, added complexity to pay for before there's a customer
need driving it.

## 2. Stack at a Glance

| Layer | Technology | Notes |
|---|---|---|
| Language (backend) | Go 1.26 | Managed via `mise` |
| Language (frontend) | TypeScript + React | Vite, no meta-framework needed at this scale. Bun as runtime + package manager. |
| Database | PostgreSQL + pgvector | Sole canonical store — facts, scopes, grants, audit log, embeddings, all transactionally atomic. Local dev via `docker-compose.yml`. **No dedicated vector DB as source of truth in CE** — see §3.2. |
| Data access | [sqlc](https://sqlc.dev), `pgx/v5` | `internal/store` — hand-written SQL in `queries/*.sql`, typed Go generated into `sqlcgen/`. Chosen over an ORM specifically to keep the hand-tuned queries (RRF fusion, scope-visibility CTEs) under our control. |
| MCP transport | `modelcontextprotocol/go-sdk` | stdio for v0 |
| Write path | Postgres-backed staged-diff state machine | Temporal is the intended long-term engine for the bouncer pipeline (see Notion §4) but is deliberately deferred — don't stand up a Temporal cluster for v0 work, see §3.3 |
| Testing | Go: stdlib `testing` + `testify/require` where assertions get noisy. TS: Vitest + React Testing Library. | |
| Deployment | Not yet decided | Don't build CI/CD or container publishing until asked — premature for v0 |

## 3. Critical Architectural Rules

### 3.1 No Direct Writes, Ever
The MCP server exposes no deterministic write endpoint. `propose-write` stages a diff in
`staged_diffs`; only a human approval (via the REST API used by the frontend, or a direct DB
action in v0) moves a diff to `committed` and materializes rows in `facts`/`fact_scopes`. If
you're tempted to add a tool or endpoint that writes directly to `facts`, stop — that defeats the
entire premise of the project (see the Notion competitive-mining writeup: every prior-art memory
project we studied skips this gate, and it's our actual differentiator, not incidental design).

### 3.2 Postgres + pgvector Is the Only Source of Truth (in CE)
Don't add a dependency on an external vector DB (Pinecone, Qdrant, etc.) as anything other than
an optional pluggable `RetrievalBackend` implementation behind an interface — CE must run on
vanilla Postgres. When writing retrieval queries: **scope-filter in the `WHERE` clause before
ranking**, never after. This is a security property (ungranted facts must never enter the
candidate set), not just a performance detail — a competitor's rewrite (CaviraOSS/OpenMemory,
see Notion) regressed exactly this property when delegating to an external vector store as a
cautionary tale.

### 3.3 Bouncer Pipeline Is Stubbed for v0 — Interface, Not Hardcoded
`ingest → classify → dedupe → stage → approve → commit` is real code today, running as a plain
Go state machine over `staged_diffs`, not a Temporal workflow. The `Classifier` and `Embedder`
are interfaces with a naive/deterministic stub implementation, because we already know we need a
second implementation later (Bedrock in production, per the Notion doc) — that's why they're
interfaces and not a bare function; it's not speculative abstraction, the second caller is already
decided. Don't wire in a real Temporal cluster or a real embedding provider without checking with
the user first — both are explicit two-way doors, deliberately left open per current direction.

### 3.4 Scope Taxonomy Is Unsettled — Don't Hardcode It
Whether default scopes need to be granular out of the box vs. user-defined is an open question
(Notion §6). Scopes are stored as plain `TEXT` (dotted strings), not a fixed enum/lookup table.
Don't add a hardcoded scope registry or CHECK constraint that bakes in a specific taxonomy.

## 4. Development Essentials

- Toolchain via `mise install` (reads `mise.toml`: Go 1.26, Bun 1.3).
- Local Postgres+pgvector: `docker compose up -d`.
- Backend: `cd backend && go run ./cmd/mcpserver` (MCP over stdio) or `go run
  ./cmd/apiserver` (REST API for the approval UI, separate process). Tests: `go
  test -p 1 ./...` with `DATABASE_URL` set to run the full suite including
  integration tests, or without it to run only the DB-free ones (they skip
  cleanly). **The `-p 1` matters**: most tests are integration tests against the
  real docker-compose Postgres, each truncating the same tables at setup — without
  `-p 1`, Go runs different packages' test binaries concurrently and they clobber
  each other's data mid-test. This is a test-runner-vs-shared-database problem, not
  flakiness in the code; don't "fix" a failure here by chasing the wrong thing.
- Frontend: `cd frontend && bun install && bun run dev`. Tests: `bun run test`.
- Migrations live in `backend/internal/db/migrations/` (timestamp-versioned `.sql` files, run
  via `golang-migrate` as a library — no separate CLI tool required). Check the latest migration
  before writing a new one; never hand-edit a migration that's already merged to `main`.
- `internal/store` is generated from SQL via [sqlc](https://sqlc.dev) (`backend/sqlc.yaml`) — hand-written
  query files live in `backend/internal/store/queries/*.sql`, generated Go in
  `backend/internal/store/sqlcgen/` (never hand-edit that directory; it's regenerated wholesale).
  After changing a query, regenerate with `DATABASE_URL` set and Postgres up:
  `cd backend && DATABASE_URL=... mise exec -- sqlc generate`. sqlc analyzes queries against a
  live database rather than static schema parsing — its static parser doesn't know pgvector's
  `vector` type or `<=>` operator, since those come from the extension, not core Postgres.

### 4.5 Known Environment Gotchas

Things that cost real time to discover once — don't rediscover them:

- **`mise`'s shell hook isn't fully active in tool-invoked (non-interactive) shells** on
  this dev machine — `go`/`bun` aren't reliably on `PATH` even after `mise install`.
  Prefix commands with `mise exec --` (e.g. `mise exec -- go build ./...`) rather than
  assuming the shims are active.
- **Docker needs elevated access in this sandbox.** Use `sudo -n docker ...`
  (passwordless sudo is configured) and expect to need to bypass the default command
  sandbox for those calls.
- **Port 5432 is already claimed** by the sibling `spritz` project on this machine (also
  7233/8233/44491 for its Temporal, 3900-3903 for Garage) — check `docker ps` before
  assuming a default port is free. This repo's Postgres uses 54322, bound to
  `127.0.0.1` only (see `docker-compose.yml`).
- **Postgres 18+ Docker images require the volume mounted at `/var/lib/postgresql`**,
  not `/var/lib/postgresql/data` — the old path silently produces an unhealthy
  container against a fresh volume (pg_ctlcluster-style layout change). Already
  handled in `docker-compose.yml`; noted here in case a from-scratch setup elsewhere
  hits it again.
- **zsh reserves `status` as a special read-only variable name.** Never use it as a
  loop/shell variable (`for status in ...` breaks) — use `hc`, `st`, or similar.
- **The full backend test suite needs `go test -p 1 ./...`, not just `go test ./...`**
  — see §4's note on why (shared-database test isolation, not flakiness).

## 5. Deployment

Not yet decided — don't build CI/CD, Dockerfiles for prod, or a Helm chart until asked. The
open-core Community Edition needs to run anywhere Postgres does (including self-hosted Proxmox
boxes per the pitch), so keep that constraint in mind if/when this section gets filled in.

## 6. Coding Standards & Workflow Rules

### Workflow
- Work in small, atomic commits — guideline is **under ~1k lines of diff per commit**, each one a
  coherent, reviewable unit (one migration, one package, one tool, one UI page — not "backend
  scaffold" as a single 3000-line commit). Write commit messages that explain **what** changed,
  **why** (tie back to the relevant Notion ticket/decision when there is one), and **how** if the
  approach isn't obvious from the diff.
- For anything genuinely ambiguous or not yet decided by the user, prefer the reversible option
  and leave a clear marker (comment, or a note in the relevant Notion task) rather than picking
  silently and moving on. Two-way doors over one-way doors when direction is unclear.
- Use proper file-reading/editing tools rather than `cat`/`sed` for inspecting or modifying files.
- Keep the Notion Tasks Tracker roughly in sync with real progress (status transitions) as you
  complete tickets — it's the team's actual view of what's done.
- **Once the repo is pushed publicly: substantial work lands as a PR, not a direct commit to
  main** — branch, push, open a PR, even for solo-authored work. Initial repo boilerplate (LICENSE,
  README, CI scaffolding, the first push of pre-existing history) is the one exception and can go
  in directly. Everything after that — new features, fixes, anything that changes behavior — gets
  a branch and a PR, both so there's a real review checkpoint (see "Review discipline" below) and
  so the public commit history reads the way an open-source project's should.

### Review discipline

The v0 build (Jul 2026) shipped 12 commits, then got an independent, adversarial
review pass afterward — 9 of the 12 needed real fixes, including a subject-spoofing
auth bypass in the MCP tools (any caller could claim to be any subject — nobody had
asked "how do we know who's calling?" at design time) and a SQL wildcard-escaping bug
that let ungranted facts leak through the scope filter. Doing the review after the
fact meant rewriting history (safely, with a snapshot branch — see
`.claude/skills/independent-commit-review`) to fold the fixes back in. That's a fine
one-time reset, but it's expensive; the same rigor is far cheaper applied per-commit,
during the build, than as a single pass at the end. Before considering a commit done:

- **For anything on an access-control or trust boundary**: explicitly answer *who is
  the caller, how do we know, and what happens if they lie?* If the answer is "we
  trust whatever they tell us," that's not a stub to note in a comment and move past
  — it's the actual gap. (Concretely: the `subject` field in MCP tool args used to be
  exactly this — a client-supplied string with no binding to anything real.)
- **Every new network-facing default must be secure by default**: bind loopback
  (`127.0.0.1`) not all interfaces, never a CORS wildcard (`*`) or dynamic
  Origin-header reflection, and always wire declared timeout config into the actual
  `http.Server` you construct — a config value that's loaded and unit-tested but
  never passed to the server it's meant to bound creates false confidence, which is
  worse than the config not existing at all.
- **Every conditional branch that encodes real logic gets a test that exercises it**
  — especially rare/edge-case branches (a classifier override, a concurrent-write
  race, a wildcard-escaping edge case), not just the happy path. If you fix a bug
  found in review, verify the fix for real: write the regression test, confirm it
  passes, temporarily revert just the fix and confirm the test now fails for the
  right reason, then restore the fix. A test that was never seen to fail hasn't
  proven anything.
- **Closed-vocabulary fields backed by a DB CHECK constraint** (status enums, depth,
  etc.) must be validated at the boundary that accepts external input, not left to
  surface as a raw driver error when the constraint fires.
- Before pushing or handing off a batch of commits meant to become standalone PRs,
  run `.claude/skills/independent-commit-review` — one fresh-eyes subagent per
  commit, no prior context, adversarial framing. Don't review your own work and call
  it independent.

### Go
- Idiomatic standard-library-first Go: `net/http`'s built-in method+path routing is enough for
  the v0 REST API — don't reach for a router framework at this scale. Table-driven tests. Return
  errors, don't panic, except at process-boot config validation (see below). `internal/` for
  everything not meant to be imported by other modules; only `cmd/` entrypoints are `main`
  packages.
- **Fail-fast on boot, no silent defaults for required config.** Read required env vars via a
  helper that errors/exits if missing (e.g. `DATABASE_URL`) — never fall back to a baked-in
  default for something that must be explicitly configured. Defaults are fine for genuinely
  optional tuning knobs (e.g. a request timeout), not for things like DB connection strings or
  API keys.
- Errors: wrap with `fmt.Errorf("...: %w", err)` for context; don't swallow errors silently
  anywhere in the bouncer/write path — see §3.1, silent partial failure is specifically dangerous
  in a consent/audit system.

### TypeScript / React
- Functional components + hooks; no class components. Keep state local (`useState`/`useEffect`)
  at this scale — don't reach for Redux/Zustand/React Query until the app actually needs them.
- Strict TypeScript (`strict: true`), no `any` without a comment explaining why it's unavoidable.
- Colocate a component's styles/tests next to it rather than in parallel mirrored directory trees.

### Database
- All schema changes go through a migration file — never hand-edit via `psql` against a running
  dev DB and call it done; the migration is what's authoritative.
- Prefer additive, backwards-compatible migrations. Ask before anything destructive (dropping
  columns/tables) once there's any real data to lose.
- Bi-temporal columns on `facts` (`valid_at`/`invalid_at`/`expired_at`/`created_at`): superseding
  a fact means soft-invalidating the old row, never deleting it — see the Notion mining writeup
  (§7) for why (audit trail, provenance, matches the pattern Graphiti uses).

---

## Caveman Mode

Terse smart-caveman register for chat/status updates. Code, commits, and PRs are always written
normal — this mode is for conversational back-and-forth only, adapted from a sibling project
(kaff) because it's a genuinely good token-efficiency trick, not because it's this project's own
invention.

Rules:
- Drop: articles (a/an/the), filler (just/really/basically), pleasantries, hedging.
- Fragments OK. Short synonyms. Technical terms exact. Code unchanged.
- Pattern: [thing] [action] [reason]. [next step].
- Not: "Sure! I'd be happy to help you with that."
- Yes: "Bug in auth middleware. Fix:"

Switch level: `/caveman lite|full|ultra|wenyan`. Stop: "stop caveman" or "normal mode".

Auto-Clarity: drop caveman for security warnings, irreversible actions, or when the user seems
confused. Resume after.

Boundaries: code/commits/PRs written normal, always.
