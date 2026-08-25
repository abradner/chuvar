# Chuvar — Agent Onboarding Guide

> Read this file first. It is the source of truth for AI agents working in this codebase.
> Design log / decisions: `docs/architecture.md` (design rationale), `docs/capability-broker.md`
> (broker workstream and its decision log), and `docs/decisions.md` (project-wide decision log)
> are the canonical design docs, not this file. This file is operational — how to build, run, and
> write code here. When the two disagree on architecture, `docs/` wins; update this file to match
> rather than the reverse.

## 1. What Is This?

**Chuvar** — the name has landed (Jul 2026). Earlier design docs and this repo's git history
refer to it as "Memory Vault," a working title used before the name was decided; that's historical
context, not a naming inconsistency to fix retroactively. The private design log that carried the
old title was migrated into `docs/` and GitHub Issues in Aug 2026 and is archive-only now.

Consent-based memory management for arbitrary agent ecosystems — "1Password meets OAuth scopes"
for personal/organisational knowledge fed into AI agents on demand. Memories are broken into
hierarchical dotted **scopes** (`identity.basic`, `projects.spritz.read`). Agents request scopes;
a human approves time-boxed, revocable, audited **grants**. Agents never write memory directly —
every proposed fact is staged as a diff and requires human approval before it commits. Exposed as
an MCP server with a companion approval UI.

The purpose in one line: **just enough, for just long enough** — chuvar lends what is yours (the
facts you know, and — via the Agent Capability Broker workstream — the authority you hold) under
grants that are scoped, timed, revocable, audited, and attributable. Borrowed, never owned. The
twelve short-form principles that follow from this live in `CLAUDE.md`; this file is their
operational form.

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
| Write path | Postgres-backed staged-diff state machine | Temporal is the intended long-term engine for the bouncer pipeline (see `docs/architecture.md`) but is deliberately deferred — don't stand up a Temporal cluster for v0 work, see §3.3 |
| Testing | Go: stdlib `testing` + `testify/require` where assertions get noisy. TS: Vitest + React Testing Library. | |
| Deployment | Not yet decided | CI exists (§5); don't build container publishing or a prod deploy until asked |

## 3. Critical Architectural Rules

### 3.0 The Trust Boundary (decided 2026-08-01)
The enforcement boundary is the **process boundary of chuvar's services, rooted in a
human-present custody unlock** — not the API alone, and not an OS-user split. The API is the sole
legitimate control surface; the database is *inside* the boundary, so reaching it directly from
agent context is by definition an attack, not a supported path. Full statement and rationale:
the decision log in `docs/capability-broker.md` (2026-08-01 entries).

Two rules fall out of it, operationally:

- **Zero ambient authority.** No root of trust (DB credentials, key material, reviewer factors)
  may be reachable from agent context through a legitimate, discoverable interface — an env var,
  a checked-in secret, an open port. The distinction that matters is *ambient reach* (must be
  zero) vs *attack-shaped actions* (`docker exec` into the DB container, reading `pgdata` bytes —
  detected and tripwired, not prevented, on a single-user box). Debt paid (#82/#86, ticket E3):
  `mcpserver` used to require `DATABASE_URL` inside the agent's own process tree; it now holds a
  revocable agent-class API token instead — see §3.6. That closure is not license to relax
  elsewhere — never add a new root of trust to an agent-reachable environment.
- **Tripwires are fail-closed.** When attack-shaped access is detected, the response is an
  outage — zeroize data-keys, seal, halt, require human re-unlock — never just a log line.

### 3.1 No Direct Writes, Ever
The MCP server exposes no deterministic write endpoint. `propose_write` stages a diff in
`staged_diffs`; only a human approval (via the REST API used by the frontend, or a direct DB
action in v0) moves a diff to `committed` and materializes rows in `facts`/`fact_scopes`. If
you're tempted to add a tool or endpoint that writes directly to `facts`, stop — that defeats the
entire premise of the project (see the competitive-mining writeup in `docs/architecture.md`: every prior-art memory
project we studied skips this gate, and it's our actual differentiator, not incidental design).

### 3.2 Postgres + pgvector Is the Only Source of Truth (in CE)
Don't add a dependency on an external vector DB (Pinecone, Qdrant, etc.) as anything other than
an optional pluggable `RetrievalBackend` implementation behind an interface — CE must run on
vanilla Postgres. When writing retrieval queries: **scope-filter in the `WHERE` clause before
ranking**, never after. This is a security property (ungranted facts must never enter the
candidate set), not just a performance detail — a competitor's rewrite (CaviraOSS/OpenMemory,
see `docs/architecture.md`) regressed exactly this property when delegating to an external vector store as a
cautionary tale. The invariant is *scope-filter before ranking wherever ranking happens* — it is
not a property of SQL. If/when the retrieval engine moves into service memory (the sealed-vault
direction, §3.5), the invariant moves with it: filter the candidate set by granted scopes before
scoring, same rule, new layer.

### 3.3 Bouncer Pipeline Is Stubbed for v0 — Interface, Not Hardcoded
`ingest → classify → dedupe → stage → approve → commit` is real code today, running as a plain
Go state machine over `staged_diffs`, not a Temporal workflow. The `Classifier` and `Embedder`
are interfaces with a naive/deterministic stub implementation, because we already know we need a
second implementation later (Bedrock in production, per `docs/architecture.md`) — that's why they're
interfaces and not a bare function; it's not speculative abstraction, the second caller is already
decided. Don't wire in a real Temporal cluster or a real embedding provider without checking with
the user first — both are explicit two-way doors, deliberately left open per current direction.

### 3.4 Scope Taxonomy Is Unsettled — Don't Hardcode It
Whether default scopes need to be granular out of the box vs. user-defined is an open question
(`docs/architecture.md`, Open questions). Scopes are stored as plain `TEXT` (dotted strings), not a fixed enum/lookup table.
Don't add a hardcoded scope registry or CHECK constraint that bakes in a specific taxonomy.

### 3.5 Sealed at Rest Is Committed
Decided 2026-08-01 (rationale: broker page decision log): fact content, embeddings, and staged
diffs become **ciphertext at rest**; the consent plane (grants, scopes, audit) stays plaintext
because it must remain SQL-enforceable. The design ticket (E7) gates the real embedder — the
current `embed.Stub{}` state means no plaintext-vector debt exists yet, and none may be created.
Operationally, starting now:

- **Never add a new plaintext-content or plaintext-secret surface** (a new column, table, export,
  or log line carrying fact content or secrets in the clear).
- **Secrets crypto is app-layer in Go, never pgcrypto** — key material must not transit SQL,
  logs, or `pg_stat_activity`.
- Honest limits: cheap memory hygiene is always taken (enclaved keys, `mlock`, non-dumpable
  processes), but chuvar is **not a hardened store** and doesn't claim to be — FIPS-style
  certification is an explicit non-goal. Don't write claims the mechanism doesn't back.

### 3.6 Launch Topology — Who Runs What, With Which Authority
Not every binary is equally trusted, and the differences are deliberate. Before
adding a binary or moving work between them, place it on this table:

| Binary | Launched by | DB role | Migrates? | Master key? |
|---|---|---|---|---|
| `cmd/apiserver` | operator | `chuvar_app` — DML, no DDL | **no** — `db.CheckSchema` only | **yes** — only process that verifies TOTP |
| `cmd/migrate` | operator | owner — the only role with DDL | yes (that's its whole job) | no |
| `cmd/mcpserver` | **an agent host** | none — `CHUVAR_AGENT_TOKEN` only | **no** — it has no database | no |
| `cmd/brokerd` | operator | `chuvar_broker` — narrow (see below) | **no** — `db.CheckSchema` only | **yes** — holds a decrypted git-signing key in guarded process memory (`internal/broker/keyring`) |
| `cmd/approver`, `cmd/pushbridge` | operator | none — `CHUVAR_API_TOKEN` only | no | no |

`cmd/mcpserver` now shares its DB-role/migrate/master-key column values with `cmd/approver`
and `cmd/pushbridge` below it — all three are API-only clients with no database connection of
any kind — but it keeps its own row rather than folding into theirs: "Launched by" is what
actually matters for this table's purpose, and mcpserver is the one binary here launched by an
agent host rather than the operator, which is why it stays the most tightly constrained of the
four despite the matching columns (see below).

**Exactly one binary migrates.** `cmd/migrate` holds DDL; nothing else does, including
`apiserver`. On a fresh database run it before starting anything — `apiserver` and `brokerd`
verify the schema and refuse to start if it is behind; `mcpserver` has no schema of its own to
check (see below).

`cmd/mcpserver` is the one that runs inside an agent's process tree, so it is the one that must
hold least — as of #82/#86 (ticket E3) it holds no database credential at all. Boot resolves a
`CHUVAR_AGENT_TOKEN` (an agent-class token, never a reviewer token — renamed off the
`CHUVAR_API_TOKEN` name `cmd/approver`/`cmd/pushbridge` still use for their own, structurally
different *reviewer* credential, closing #120's naming collision) and calls
`GET /api/agent/whoami` against the agent-only listener (`CHUVAR_AGENT_ADDR`); a successful
response already proves `apiserver`'s own `db.CheckSchema` passed at its boot, so mcpserver's
boot check delegates schema-currency to `apiserver` rather than re-implementing it. A bad or
revoked token fails boot with a message distinct from an unreachable backend — see
`docs/operations.md`'s agent-token section for the full mint/deploy/rotate procedure.

`chuvar_agent` was derived from what mcpserver's code used to call directly, back when it held
`DATABASE_URL`: SELECT on `grants`, `grant_scopes`, `facts`, `fact_scopes`, `staged_diffs`,
`grant_requests`; INSERT on `staged_diffs`, `grant_requests`, `audit_log`; no access at all to
`reviewer_tokens` or `data_keys`; INSERT without SELECT on `audit_log` (append, never read
back). **As of #82/#86 this role is unused by mcpserver and deprecated** — mcpserver holds no
database credential of any kind, so nothing connects as `chuvar_agent` today. It is retained
rather than dropped: `chuvar_agent` is a cluster-global, stamped role (`docs/operations.md`,
"Roles are cluster-global"), and dropping one is its own migration with its own risk (a
same-named future role, a deployment caught mid-upgrade) — while a dormant `NOLOGIN` role that
nothing can authenticate as carries no standing risk of its own. Per principle 7's deletion
test: removing this role today would change nothing about what's possible, only tidiness, so
dropping it is a deliberate future PR's job, not an incidental one.

**The residual gap is closed: mcpserver no longer holds a database credential.** #82/#86
replaced it with a revocable agent-class API token (`agent_tokens`, structurally distinct from
`reviewer_tokens` — its own table, its own hash namespace, so an agent token can never
authenticate as a reviewer; see `docs/decisions.md`), presented to a separate agent-only HTTP
listener (`CHUVAR_AGENT_ADDR`) that the reviewer surface is never mounted on, so a process
holding only an agent token cannot reach reviewer routes even at the network layer. Identity is
resolved server-side from the token on every request (`agentFromContext`) — mcpserver never
declares its own subject the way `MCP_SUBJECT` used to let it. Never widen `chuvar_agent` (it
is dormant, see above) and never add a new root-of-trust to any binary an agent launches — that
constraint outlives the specific credential it was originally written about.

`chuvar_broker` (brokerd, issues #95/#79) is narrower still and touches a disjoint
set of tables: SELECT on `grants`, `grant_scopes`, `capability_grant_identities`,
`capability_grant_tokens`; INSERT-without-SELECT on `audit_log`, same append-only
posture as `chuvar_agent`. No access to `facts`/`fact_scopes`/`staged_diffs` at
all — brokerd never touches the facts path (`internal/broker`'s package doc) — nor
to `reviewer_tokens`/`data_keys`. See
`internal/db/migrations/20260809150000_broker_role.up.sql` and
`docs/operations.md`'s role table for the provisioning step.

New tables are granted to `chuvar_app` automatically (`ALTER DEFAULT PRIVILEGES`) and to
`chuvar_agent`/`chuvar_broker` **never** — widening either role's view is always a
deliberate act.

### 3.7 Credentials Come From Files, Not the Environment
Every required credential — `DATABASE_URL`, `CHUVAR_API_TOKEN`,
`REVIEWER_BOOTSTRAP_TOKEN` — is read by `config.Secret`, which prefers `<KEY>_FILE`
(a `0600` file, refused if group/other-readable) over `<KEY>`. An environment variable is
readable via `/proc` by anything running as the same user, is inherited by every child
process, and turns up in crash dumps — a file read once at boot is narrower on all three,
and matches how systemd, Docker and Kubernetes expect secrets to arrive. Plain `<KEY>` still
works for local development.

The Postgres owner password is interpolated in `docker-compose.yml`
(`${CHUVAR_DB_PASSWORD:-chuvar_dev_only}`) from a gitignored `.env`. **The fallback is not a
secret**: leaving it as the only option meant any local process could read the owner
credential out of a checked-in file and connect as superuser, which bypasses §3.6's roles
entirely. Never reintroduce a literal credential into a tracked file.

## 4. Development Essentials

- Toolchain via `mise install` (reads `mise.toml`: Go 1.26, Bun 1.3).
- Local Postgres+pgvector: `docker compose up -d`.
- Backend: `cd backend && go run ./cmd/mcpserver` (MCP over stdio) or `go run
  ./cmd/apiserver` (REST API for the approval UI, separate process). `mcpserver`
  and `apiserver` both verify the schema and never migrate (§3.6) — on a fresh database run
  `go run ./cmd/migrate` first; nothing else will apply migrations for you. `apiserver`
  needs a custody master key to seal reviewer TOTP secrets — on a first run pass
  `CHUVAR_CUSTODY_CREATE=1` to mint one (see `docs/operations.md`, "The master
  key"). It is opt-in so a later start with a missing key fails loudly instead of
  minting a replacement that opens nothing. Tests: `go
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
- **Don't assume port 5432 is free** — other Postgres instances often use it, and this
  dev machine runs several projects' service stacks side by side; check `docker ps`
  before assuming any default port is free. This repo's Postgres uses 54322, bound to
  `127.0.0.1` only (see `docker-compose.yml`).
- **Postgres 18+ Docker images require the volume mounted at `/var/lib/postgresql`**,
  not `/var/lib/postgresql/data` — the old path silently produces an unhealthy
  container against a fresh volume (pg_ctlcluster-style layout change). Already
  handled in `docker-compose.yml`; noted here in case a from-scratch setup elsewhere
  hits it again.
- **zsh reserves `status` as a special read-only variable name.** Never use it as a
  loop/shell variable (`for status in ...` breaks) — use `hc`, `st`, or similar.
- **`gh stack submit` creates PRs as drafts**, which silently breaks the batch-review
  workflow ("open every PR ready-for-review immediately") and blocks a merge train
  mid-run. Mark them ready explicitly. Related: `gh pr merge` and the REST
  `PUT .../merge` both **refuse PRs that belong to a gh-stack** — `gh stack unstack <n>`
  frees them without touching the PRs or their base branches. This repo auto-deletes
  merged branches and GitHub auto-retargets children, so a redundant retarget returns a
  harmless 422; verify the base rather than treating it as a failure.
- **`go test -race` does not work on this machine.** ThreadSanitizer aborts with
  `unsupported VMA range / Found 47 - Supported 48` — the Pi's kernel uses a 47-bit
  virtual address space and TSan requires 48. This is a host limitation, not a
  failing test: drop `-race` locally and let CI (x86) cover it.
- **The full backend test suite needs `go test -p 1 ./...`, not just `go test ./...`**
  — see §4's note on why (shared-database test isolation, not flakiness).

## 5. CI and Deployment

**CI exists** (`.github/workflows/ci.yml`): on every PR and on push to `main`, a
`dorny/paths-filter` job splits the diff into `backend/` and `frontend/` halves so a
one-sided change only pays for its own jobs. Backend runs `go vet`, `go build`,
`go test -p 1 ./...` against a `pgvector/pgvector` service container, and an **sqlc drift
check** (regenerate, then require `internal/store/sqlcgen/` to be unchanged). Frontend runs
`bun install --frozen-lockfile`, `oxlint`, `bun run build` (tsc + vite) and `vitest`. PR runs
cancel their own superseded predecessors; runs on `main` do not, since those are what
`bin/release-tag` checks. The toolchain comes from `mise.toml` via `jdx/mise-action` — add a
tool there, not in the workflow.

Note that a **skipped job is not a passing job**: a frontend-only PR shows no backend job,
which means the Go suite never saw that commit.

**Deployment is still not decided** — don't build container publishing, prod Dockerfiles, or a
Helm chart until asked. The open-core Community Edition needs to run anywhere Postgres does
(including self-hosted Proxmox boxes per the pitch), so keep that constraint in mind if/when
this gets filled in. `bin/release-tag` cuts a `v<UTC timestamp>` tag at main's tip after a
merge train; today that tag only marks a release point, and an image build (when there is one)
should trigger from it.

## 6. Coding Standards & Workflow Rules

### Workflow
- Work in small, atomic commits — guideline is **under ~1k lines of diff per commit**, each one a
  coherent, reviewable unit (one migration, one package, one tool, one UI page — not "backend
  scaffold" as a single 3000-line commit). Write commit messages that explain **what** changed,
  **why** (tie back to the relevant GitHub issue or `docs/decisions.md` entry when there is one), and **how** if the
  approach isn't obvious from the diff.
- For anything genuinely ambiguous or not yet decided by the user, prefer the reversible option
  and leave a clear marker (comment, or a note on the relevant GitHub issue) rather than picking
  silently and moving on. Two-way doors over one-way doors when direction is unclear.
- **Ground decisions in the real system** — check the actual schema, hardware, and code before
  arguing from theory. Recent example: the sealed-vault decision (2026-08-01) turned on two
  checked facts (`content_tsv` is a generated column; flat vector scan timings on the actual
  deployment host), both of which overturned the on-paper plan. A feasibility argument that
  hasn't touched the schema is a guess.
- Use proper file-reading/editing tools rather than `cat`/`sed` for inspecting or modifying files.
- Keep GitHub Issues roughly in sync with real progress (close, label, and comment as you
  complete work) — it's the team's actual view of what's done.
- **Once the repo is pushed publicly: substantial work lands as a PR, not a direct commit to
  main** — branch, push, open a PR, even for solo-authored work. Initial repo boilerplate (LICENSE,
  README, CI scaffolding, the first push of pre-existing history) is the one exception and can go
  in directly. Everything after that — new features, fixes, anything that changes behavior — gets
  a branch and a PR, both so there's a real review checkpoint (see "Review discipline" below) and
  so the public commit history reads the way an open-source project's should.

- **Multi-PR batches follow `.claude/skills/batch-review`** — stacked single-commit PRs, all
  review feedback write-only until a single synthesis pass, one followup PR at the top of the
  stack, merge bottom-up. Author-side agents: a review comment or CI event on a non-followup
  batch PR is a ledger entry, not a work order — do not respond piecemeal. Reviewers (human or
  bot): review fully as normal; unanswered comments on batch PRs are the workflow operating as
  designed, not feedback being ignored.

- **Security-critical features can be built competitively — `.claude/skills/competition-build`.**
  2–3 independent implementations of one brief, adversarial judges, only the survivor becomes a
  PR, escalate a tier only when every attempt has blocking holes. Opt-in, for trust-boundary work
  or unattended runs; it decides *what* enters the batch flow, it doesn't replace it. Whenever
  more than one branch is in flight against the same package — competitively or not — run
  `.claude/skills/stack-integration-check` before opening the PRs.

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
  surface as a raw driver error when the constraint fires. Apply the **deletion
  test** to keep this from becoming two half-controls: the CHECK constraint is the
  enforcement and exists exactly once; the boundary validation is legibility, and
  deleting it must change politeness (a friendly 400 vs an ugly 500), never
  possibility. If deleting either check would make a new state *possible*, you have
  enforcement in two shapes, and the two will drift.
- **Security claims name their adversary — and must hold.** A comment or doc making
  a security claim states which adversary it defends against; if the claim depends
  on unshipped work, it says so in-place ("stated, not enforced"), and a stopgap
  records the bar it doesn't meet. Cautionary example: the TOTP migration shipped
  claiming "a factor shell access alone cannot produce" while the secret sat
  plaintext one loopback connection away — an aspirational security comment is a
  bug, not documentation.
- **Actor identity derives from the authenticated credential, never the request
  body.** `decided_by`/`approved_by`/`revoked_by`/`renewed_by` (and any successor
  field) come from the authenticated reviewer/agent token on every mutation path.
  Preserve this on each new path you add — it's the difference between an audit log
  and a guest book.
- Before pushing or handing off a batch of commits meant to become standalone PRs,
  run `.claude/skills/independent-commit-review` — one fresh-eyes subagent per
  commit, no prior context, adversarial framing. Don't review your own work and call
  it independent.
- **Per-branch review is blind to what happens between branches.** Two branches can
  each be correct, each be green, and still implement the same shared function in
  opposite directions — the suites pass because each only tests the cases that behave
  identically either way. Run `.claude/skills/stack-integration-check` on the
  combination as soon as the candidate branches exist. Cautionary example: two
  branches shipped opposite `scope.Covers` semantics for untargeted-grant-vs-targeted-
  request, and a third silently deleted a validation chokepoint the branch below it
  had introduced. Both were caught by diffing branches against each other, not by any
  test run.
- **Never relay a subagent's finding without checking it against git.** Read the diff,
  grep the branch, run the command — then say whether you're reporting what you
  verified or what you were told. Agents commit correct work and then fail at
  reporting it; two agents contradicting each other are usually both right about
  different artifacts.

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

**UI component standard** (decided 2026-08-08, PR #56 review; `pages/tokens/` is the exemplar).
A feature splits into three roles, usually two-and-a-bit files under `pages/<feature>/`:

| Role | File | Owns | Must not |
|---|---|---|---|
| Hook | `use<Feature>.ts` | Fetching, state, domain rules, guard ceremonies (`confirm`/`prompt`). Data-centric; returns values + callbacks. | Contain JSX |
| View | `<Feature>View.tsx` | Props in, JSX out. May own purely-local UI state (a controlled input). | Import from `api/`; decide *when* anything may happen |
| Page | `<Feature>.tsx` | Layout + plumbing: call the hook, hand the result to the view. | Grow logic. It stays ~thin, or the split has failed |

Why this shape and not classic container/presenter: with hooks, a component whose only job is
holding state and passing props is a layer with no behaviour of its own — the hook *is* the
container. The observable payoff, and the test for whether a refactor did it right: **the view's
test file needs no `vi.mock`, no async harness** (`TokensView.test.tsx` vs `Tokens.test.tsx`).
Guard ceremonies live in the hook so any future view over the same data inherits them rather than
re-implementing them; they're politeness, not enforcement (the server is the enforcement — see
the deletion test above), but politeness that shouldn't silently vanish in a redesign.
Split further (separate layout component, shared `components/` primitives) only when a second
consumer actually exists — same "second caller is decided, not speculative" bar as §3.3.
Behavioral tests exercise the page (hook+view integrated); view tests cover rendering given
props. `Grants.tsx`/`StagedDiffs.tsx` predate this standard and are tracked for retrofit in
issue #90 — don't copy their single-blob shape into new work.

- UI-affecting PRs include a screenshot (or before/after pair) in the description — reviewers
  shouldn't have to run the branch to see what changed.

### Database
- All schema changes go through a migration file — never hand-edit via `psql` against a running
  dev DB and call it done; the migration is what's authoritative.
- Prefer additive, backwards-compatible migrations. Ask before anything destructive (dropping
  columns/tables) once there's any real data to lose.
- Bi-temporal columns on `facts` (`valid_at`/`invalid_at`/`expired_at`/`created_at`): superseding
  a fact means soft-invalidating the old row, never deleting it — see the mining writeup in
  `docs/architecture.md` for why (audit trail, provenance, matches the pattern Graphiti uses).

---

## Caveman Mode

Terse smart-caveman register for chat/status updates. Code, commits, and PRs are always written
normal — this mode is for conversational back-and-forth only, adapted from a sibling project
because it's a genuinely good token-efficiency trick, not because it's this project's own
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
