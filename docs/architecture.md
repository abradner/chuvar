# Chuvar Architecture: Design Rationale

This document is the canonical design rationale for Chuvar — the *why* behind
the decisions `AGENTS.md` and `docs/operations.md` describe operationally.
It was migrated from the project's private design log on 2026-08-08; the
decision dates below are the original dates those calls were made, not the
migration date. Where the source material left a question open, it stays
open here — this is a record of what was decided and why, not a place to
retroactively resolve what wasn't.

Read `AGENTS.md` first if you haven't — it's the source of truth for how to
build and run this repo. This document exists to answer the questions
`AGENTS.md` deliberately doesn't: why Postgres and not a vector database, why
a staged-diff write path instead of direct writes, and what the rest of the
memory-for-agents space already does (so it's clear which parts of Chuvar are
actually new).

## The problem

Chuvar is a consent-based memory management layer for arbitrary agent
ecosystems — "1Password meets OAuth scopes" applied to the personal and
organisational knowledge fed into AI agents on demand. Knowledge is broken
into hierarchical, dotted **scopes** (`identity.basic`,
`preferences.communication`). Agents request scopes; a human approves grants
that are time-boxed, revocable, and fully audited. As sessions progress, an
agentic layer drip-feeds new facts back into memory — classifying, deduping,
and proposing edits, always subject to review before anything commits.

Data privacy and portability are design constraints from day one, not
add-ons: the canonical store must run anywhere Postgres does, and nothing in
the free edition depends on a proprietary managed service.

## Competitive landscape

*(decided Jul 2026)*

The conclusion driving Chuvar's shape: the *memory storage* layer is
crowded; the *scoped-consent* layer is not. No project surveyed combines
OAuth-style granular consent grants with a queryable personal knowledge
store.

**Memory/storage layer (crowded):**

- **OpenMemory MCP** (Mem0) — the closest neighbour at the product level.
  Local-first, private, ships a dashboard, lets a user add/browse/delete
  memories and control per-client access. Access control is coarse
  (per-client), not scoped per-fact.
- **Zep / Graphiti** — temporal knowledge graphs that track how facts change
  over time with provenance back to source data.
- **Letta** (formerly MemGPT) — memory as structured "blocks" (a persona
  block, a human block, etc.) attached to an agent.
- **Redis agent-memory-server**, the official
  `@modelcontextprotocol/server-memory`, and well over a hundred others in
  the various MCP server directories — mostly flat stores with
  keyword/semantic search and no fine-grained consent model.

**Access-control layer (active, but focused on credentials, not knowledge):**

- **HashiCorp Vault** — now has native AI-agent support: per-request OAuth
  2.0 RAR-based authorization, policy intersections (owner policy ∩ agent
  baseline ∩ delegation ceiling), and full delegation/consent tracking. The
  closest conceptual sibling to Chuvar's grant model, but scoped to
  credentials rather than structured, queryable knowledge.
- **AgentVault and similar** — encrypted local credential vaults scoped
  per-agent, but they treat payloads as opaque secrets, not structured
  content a system can classify, dedupe, or rank.

**The wedge:** OAuth-grant semantics plus a 1Password-style approval UX,
applied to queryable personal knowledge rather than opaque secrets or coarse
per-client toggles. Section "Competitive codebase mining" below re-tests this
conclusion against six actual codebases rather than public descriptions of
them, and it holds.

## Scope and consent model

- Scopes are hierarchical and dotted, OAuth-flavoured (`identity.basic`,
  `preferences.communication`, or — to use the actual convention this
  codebase ships with — `projects.spritz.read` for a per-project read scope).
- A fact can carry **multiple** scope tags at once — a single fact like "is
  planning a family event in March" touches identity, relationships,
  finances, and schedule simultaneously — so grant evaluation is an
  **intersection** across a fact's tags, not a match against any single one.
- Classification into scopes happens at write time, inside the bouncer
  pipeline (below) — this is where a small classifier model earns its keep.
- **Insufficient-scope flow:** when an agent asks a question the current
  grant can't answer, the server returns a structured "insufficient scope"
  response naming exactly which scopes would be needed, and the front end
  can surface that as an approval request. MCP's elicitation capability is a
  candidate for carrying this in-band rather than out-of-band.
- **Progressive disclosure:** grants carry depth levels — summary →
  facts → full provenance — so a cheap default answer doesn't require
  full-detail access. Depth is enforced on the read path (as of Aug 2026,
  with `full` defined as content plus provenance); the known residual is
  that the write path's dedupe verdict can still leak past a depth limit —
  see "Open questions."
- Writes are never direct, for any grant, at any depth: every write is a
  *proposal*, reviewed like a pull request before it lands. That rule is
  covered in full in `AGENTS.md` §3.1; the rationale for it is the next
  section.

## The bouncer: write path

MCP intentionally exposes no deterministic write endpoint. Every write
routes through an agentic "bouncer" that provides guardrails and does
paraphrasing/dedup before anything is staged for human approval.

**Pipeline:** `ingest → classify (scopes) → dedupe → stage diff → await
human approval → commit`. This is a textbook human-in-the-loop workflow;
Temporal is the intended long-term execution engine for it (see `AGENTS.md`
§3.3 for why it's deliberately not wired in yet).

**Poisoning defence.** Semantic dedup doubles as the tripwire against
manipulated or poisoned writes: the incoming fact is embedded and checked
against existing memory by nearest-neighbour. A near-duplicate becomes a
merge/update proposal instead of a new fact; a near-duplicate that is also
**contradictory** is flagged for human review rather than silently applied.
Painless review is treated as a first-class feature of the design, not a
compliance checkbox, because it's the primary defence this system has
against an agent — confused, misled, or adversarial — trying to plant a
false memory. (Adversary named per the project's own claims-must-hold rule:
this defends against a *write-side* poisoning attempt reaching committed
memory, not against a human reviewer being socially engineered into
approving something they shouldn't.)

## Storage architecture

*(decided Jul 2026)*

**Decision: Postgres + pgvector is the single canonical store.** Facts,
scope tags, grants, audit log, and the embedding column all live in one
transactionally-consistent place — a staged write commits the fact, its
scopes, and its vector atomically, or none of them commit.

**Why not a dedicated vector database (e.g. Pinecone) as the source of
truth:**

- Every core operation here is deterministic and relational — "everything
  in `identity.professional` readable under grant G," a complete audit
  trail, revocation — and fighting an ANN-first engine to recover exactness
  is the wrong trade.
- Portability. Embeddings are lossy, model-specific, and go stale the moment
  the embedding model changes. Canonical text plus metadata is portable
  forever; vectors are cheap to regenerate from it. The dependency arrow
  must point text → vectors, never the reverse.
- Scale mismatch. Personal memory is thousands to low tens of thousands of
  facts. Pinecone-class stores are built for hundreds of millions of
  vectors; at Chuvar's scale, exact cosine similarity over the full set
  costs single-digit milliseconds.
- The Community Edition can't carry a hard dependency on someone else's
  proprietary managed cloud — that would contradict both the open-core model
  and the privacy/portability pitch itself.

**Retrieval** is hybrid: `tsvector` keyword search fused with pgvector
cosine similarity via Reciprocal Rank Fusion (RRF) — roughly a hundred lines
of SQL, no external dependency. **Scope filtering happens in the `WHERE`
clause, before ranking, on every query that touches candidate facts** —
ungranted facts must never enter the candidate set. This is stated as a
security property, not a performance detail, because of what it defends
against: a query whose result — even just a rank or a verdict, not the raw
content — can otherwise be used as an oracle for facts a caller was never
granted. (The "Competitive codebase mining" section below documents a real
regression of exactly this property in the closest comparable codebase, and
a related oracle-style leak Chuvar's own second-round review found in its
*own* dedupe path — filter-before-rank is a rule about every ranking site,
not a property that happens to hold for one endpoint.)

**ParadeDB / BM25 extensions — investigated, not adopted (for now).**
ParadeDB's `pg_search` brings true BM25 (via Tantivy) into Postgres and is
the standard recommendation once an application needs first-class hybrid
search at scale. It wasn't adopted, for four reasons:

1. BM25's advantages — inverse document frequency, document-length
   normalization — matter most on large, heterogeneous documents. Chuvar's
   corpus is thousands of short, bouncer-paraphrased facts of fairly uniform
   shape, where plain `tsvector` plus vectors already covers the
   exact-term-vs-paraphrase split well.
2. It's a compiled extension requiring a blessed Postgres image or Helm
   chart, which undermines the "CE runs on any Postgres" constraint.
3. Managed-platform support is patchy — Neon dropped `pg_search` for new
   projects in March 2026.
4. Its custom `@@@` query syntax sits awkwardly against scope-based
   row-level filtering.

`pg_textsearch` (Tiger Data/Timescale, open-sourced early 2026,
production-ready mid-2026) is a lighter-weight BM25 option worth revisiting
if a real corpus ever shows retrieval quality is the actual bottleneck —
which isn't expected, since quality here is dominated by how well the
bouncer writes facts in the first place, not by ranking cleverness.

**The open-core seam** is a `RetrievalBackend` interface. Community Edition
ships vanilla `pgvector` + `tsvector` + RRF, zero exotic dependencies, and
runs anywhere Postgres does, including a self-hosted box. Paid tiers can
plug in ParadeDB, `pg_textsearch`, Qdrant, or a managed vector store behind
that same interface if a real workload ever justifies it — without CE ever
depending on any of them.

**Agentic layer:** the production embedder target is AWS Bedrock; a tiny
in-memory model stands in for prototyping today (see `AGENTS.md` §3.3 for
why that's an interface, not a shortcut).

## Competitive codebase mining

*(Jul 2026 — the competitive-mining writeup that `AGENTS.md` §3.1/§3.2 cite;
this section is that writeup, migrated here from the private design log.)*

Before writing v0, six related codebases were shallow-cloned and actually
read — as temporary, gitignored working copies, never vendored into this
repo — to steal working patterns rather than reinvent them: **mem0 /
OpenMemory MCP**, the **official MCP reference memory server**, **Graphiti**
(Zep's temporal knowledge graph), **Letta** (formerly MemGPT), **Redis
agent-memory-server**, and **CaviraOSS/OpenMemory** (a from-scratch rewrite,
at the time mid-flight on a Postgres+pgvector architecture — the closest
architectural neighbour of everything surveyed).

**Headline finding, repeated across all six:** nobody combines scoped-consent
grants with a staged, human-approved write path. Every project examined
writes memory directly and deterministically — mem0's `add_memories`, the
reference server's `create_entities`, Graphiti's `add_memory` /
`add_triplet`, Letta's `core_memory_append`, Redis's
`create_long_term_memories`, and CaviraOSS's `openmemory_store` all commit
synchronously with no review gate. Where "smart" merge/dedup logic exists —
mem0's LLM-driven ADD/UPDATE/DELETE, Graphiti's contradiction resolution,
Redis's three-pass dedup cascade — it's fully automatic; none of them flag a
contradictory near-duplicate for a human to look at. This is the direct
evidence behind Chuvar's central bet: the bouncer's stage → approve → commit
gate is the actual wedge, not a redundant layer bolted onto a solved
problem.

**Access control, project by project:**

- **mem0 / OpenMemory** — coarse: a generic subject/object/effect ACL
  table, used in practice as one boolean per client app (`App.is_active`)
  plus optional per-memory-ID allow/deny lists. Its `categories` taxonomy is
  cosmetic — never consulted by the permission check. No scope-based grants
  at all.
- **Letta** — a stubbed dead end. `apply_access_predicate` takes a
  `read`/`write`/`admin` access-level parameter and then literally discards
  it (`del access`), falling back to flat org-ID filtering. This confirms
  Letta punted on exactly the multi-owner problem that's still open for
  Chuvar (see "Open questions") — there was no prior art to borrow here.
- **Redis agent-memory-server** — flat `namespace` / `user_id` / `session_id`
  tags, ANDed together. Its "scopes" are OAuth API-permission strings
  gating endpoints, not data visibility.
- **CaviraOSS/OpenMemory** — flat tenant fields (`user_id` / `project_id`)
  plus a per-memory JSONB `contracts` object (`recall_allowed`,
  `retention_policy`, `sensitivity`, `expires_at`). Single-tier, not
  hierarchical or intersecting.
- **Net:** Chuvar's hierarchical dotted-scope, intersection-grant model has
  no real precedent in the space surveyed. Worth stating plainly as a
  differentiator rather than an implementation detail.

**Retrieval design — validated, with one important caveat.** CaviraOSS's
rewrite independently arrived at the same core security property Chuvar
adopted: all tenant/project/temporal/contract filters sit in the SQL `WHERE`
clause of a CTE, evaluated *before* the `ORDER BY` vector-distance ranking
(`repository.ts`, a partial HNSW index on non-null embeddings). That's direct
external validation of the filter-before-rank design. But CaviraOSS's own
`OM_VECTOR_STORE` escape hatch — delegating to an external vector store like
Qdrant or Pinecone — **regresses that exact property**: its own
`docs/vector-stores.md` states that path "queries the external vector store
first, then loads matching rows from Postgres with tenant/project filters" —
i.e., filter *after* rank. That's precisely the anti-pattern the
"Postgres+pgvector only, no pluggable vector-DB source of truth in CE"
decision above exists to avoid, observed as a live property of the closest
comparable codebase — not a hypothetical risk. Separately, CaviraOSS's
retrieval is vector-OR-substring-ILIKE, not a true fused-rank hybrid; Chuvar's
`tsvector` + cosine + RRF is a genuine improvement over the strongest prior
art found, not just parity with it.

**Schema and provenance patterns adopted into the Postgres design:**

- **Bi-temporal columns** (from Graphiti): `valid_at` / `invalid_at` /
  `expired_at` / `created_at` — an event-time pair plus a system-time pair.
  On contradiction, Graphiti soft-invalidates the old edge rather than
  deleting or merging it; both versions persist. Chuvar's `facts` table does
  the same: never hard-delete on supersession, which directly serves the
  audit and provenance requirement.
- **Dual tag storage** (from Letta's `passage.py` / `passage_tags`): a
  JSON/array column on the row plus a normalized junction table for the tags
  actually used in filtered search. Chuvar's `fact_scopes` table follows
  this rather than relying on an array column alone — a proper junction
  table indexes better for the `WHERE`-clause scope filter above.
- **Append-only history for both writes and reads** (mem0's
  `memory_status_history` and `memory_access_logs`; Letta's
  `block_history`): the direct precedent behind logging grants being *used*
  to read, not only facts being written.
- **Partial HNSW index** on the embedding column, indexing only non-null
  rows (CaviraOSS) — a cheap, direct addition to the retrieval schema.

**MCP tool-design conventions copied from the official reference memory
server** (the cleanest minimal example found): schema-validated input and
output per tool (Zod in the reference server's TypeScript; Go structs and
generated JSON Schema here); tool annotations (`readOnlyHint`,
`destructiveHint`, `idempotentHint`) — Chuvar's `read_with_scope_check`
maps to read-only, `propose_write` to non-destructive, since it stages
rather than commits;
dual-format tool responses (`content: [{type: "text", ...}]` and
`structuredContent`) so both an LLM caller and a programmatic one work; and
a consistent, always-structured error convention — the reference server
throws on some missing-entity cases and silently no-ops on others, which is
a specific mistake called out to avoid in `propose_write`, given it sits
inside a consent/audit system where a silent partial failure is actively
dangerous.

**Classify/dedupe bootstrap.** Graphiti's `dedupe_edges` prompt draws a
clean line between "duplicate" and "contradiction" — same relationship, but
an updated value (e.g. "software engineer" → "senior engineer") counts as a
contradiction — which is a good starting point for the bouncer's own
classify step, even though Graphiti then resolves the contradiction
automatically where Chuvar flags it for review instead. Redis's debounced
trailing-extraction pattern (batching conversation turns before triggering
extraction) is a reasonable model for batching the bouncer's ingest step
rather than triggering it on every message.

## Open questions

These are open by design, not by omission — resolving them prematurely would
mean guessing ahead of real usage. They stay open here rather than being
editorially closed:

- **Scope taxonomy.** How granular do default scopes need to be out of the
  box, versus left fully user-defined? (Operationally: scopes are stored as
  plain `TEXT`, not a fixed enum, specifically so this stays unresolved
  without a migration — see `AGENTS.md` §3.4.)
- **Grant UX specifics.** Push notification vs. in-band MCP elicitation vs.
  dashboard-only approval — which channel, or combination, actually gets
  used.
- **Multi-tenant / team story for paid editions.** How grants compose when
  more than one human owns facets of the same vault. Directly related: none
  of the six codebases surveyed above had usable prior art for this either
  (Letta's stubbed `access` parameter is the closest thing to an answer, and
  it isn't one).
- **The dedupe-verdict oracle.** Grant depth is enforced on the read path,
  but the write path's dedupe check remains a content-confirmation oracle:
  a caller holding a scope at summary depth can propose a guessed fact and
  learn from the dedupe verdict whether the exact content already exists.
  The obvious fix — filtering dedupe candidates down to the proposer's own
  view — breaks the legitimate dedup the bouncer exists to do. No agreed
  fix yet; tracked as an open issue.

## Project history

Chuvar's v0 slice — the scope model, staged-diff approval, hybrid retrieval,
and the first three MCP tools — was built end to end in Jul 2026, then put
through two rounds of independent, adversarial review before anyone else saw
it. Those reviews are why two of this document's rules are stated as
invariants rather than preferences: *filter before rank, at every ranking
site* (the write path's dedupe check had regressed it, briefly making the
dedupe verdict an existence oracle for ungranted facts — fixed, with one
residual still open: see "Open questions"), and *audit every mutation, not
just reads*. The broader findings and the per-commit practices they produced
live in `AGENTS.md`'s "Review discipline" section; the long-form commit
messages on `main` are the primary record. The project's name — Chuvar — and
its Apache-2.0 license were both decided in Jul 2026; see the README's
"License and how this project makes money" section for the licensing
reasoning.
