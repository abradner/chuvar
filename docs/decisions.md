# Chuvar — Decision Log

This is Chuvar's public, append-only record of decisions that shaped the
project: what was chosen, what was rejected and why, and what it cost. Newest
entries are at the top.

**Append-only, supersede-never-erase.** Nothing here is edited to look right
in hindsight. A decision that later changes gets a *new* entry marked
`Status: superseded by <date/link>`; the original stays, unedited, as the
record of what we believed and why at the time — history is evidence, not a
draft. This mirrors how Chuvar treats facts in its own data model: superseded,
never deleted.

**Provenance.** This log was migrated from a private internal design log on
2026-08-08, when the project moved off that tool ahead of going open source.
Entry dates below are the *original* decision dates, preserved as-is; only the
location moved.

**Scope.** This is the project-wide log. The Agent Capability Broker
workstream keeps its own, workstream-local decision log in
[capability-broker.md](capability-broker.md); the three of its decisions that
are load-bearing project-wide (the 2026-08-01 trust-boundary and sealed-vault
entries, and the 2026-07-27 signing-policy entry) appear in both places —
this log carries the decision record, the broker doc carries the surrounding
workstream context. Both are append-only, so the two copies don't drift; if
they ever appear to disagree, the newer dated entry wins.

---

## 2026-08-08 — UI feature components split into hook / view / page

**Every frontend feature splits into a data hook, a presentational view, and a
thin page that wires them together — no other shape for new UI work.**

**Context.** Two existing screens (`Grants`, `StagedDiffs`) were single-file
blobs mixing fetching, state, guard prompts (`confirm`/`prompt`), and JSX.
Testing them required mocking the network inside a component test. PR #56's
review of the token-enrollment UI made the fix concrete and reusable: split
into `use<Feature>.ts` (fetching, state, domain rules, guard ceremonies —
data-centric, no JSX), `<Feature>View.tsx` (props in, JSX out, no imports from
`api/`), and `<Feature>.tsx` (layout plumbing only, stays thin or the split
has failed).

**Rejected alternatives.**
- *Classic container/presenter split* — rejected as the wrong frame now that
  hooks exist: a component whose only job is holding state and passing props
  down is a layer with no behaviour of its own once a hook can hold that
  state directly. The hook *is* the container.
- *Leave `Grants`/`StagedDiffs` as-is and only apply the standard to new
  code* — accepted as the practical starting point (see costs below), not
  rejected outright.

**Accepted costs.** `Grants.tsx` and `StagedDiffs.tsx` predate the standard
and were not retrofitted immediately; they're tracked for a follow-up rather
than blocking the standard's adoption. New work must not copy their shape.
Split further (separate layout components, shared primitives) only once a
second real consumer exists — not preemptively.

**Status:** standing.

---

## 2026-08-07 — Least-privilege database roles

**Three Postgres roles, not one: an owner that can run DDL, an app role that
can't, and a narrower agent role that can't even read what it just wrote.**

**Context.** Through v0, every service connected to Postgres as the same
owner-privileged credential. Anything holding `DATABASE_URL` — including
`mcpserver`, the process that runs inside an agent's own tree — could
`INSERT INTO grants` directly and mint itself every scope, with a matching
(self-authored) audit row. That defeats the consent model in two SQL
statements, and no API-layer control would ever see it happen.

`chuvar_agent` (used by `mcpserver`) can read grants/scopes/facts, append to
`audit_log`, and stage diffs and grant requests — but cannot write `grants`,
cannot read `reviewer_tokens` or `data_keys`, cannot read *other subjects'*
staged proposals, and holds only column-level `SELECT` on its own inserted
rows (just enough to learn the row's own id, nothing else — Postgres requires
`SELECT` on every column a `RETURNING` clause reads, so narrowing that
clause required narrowing the grant too). `chuvar_app` (used by `apiserver`)
gets full DML but no DDL. Only `cmd/migrate`, run by the operator, holds the
owner role.

**Rejected alternatives.**
- *OS-user separation per service* — considered as part of the broader trust-
  boundary question and rejected: policy-fragile on Linux, the wrong tool on
  macOS, and hollow under Docker (the `docker` group is root-equivalent, and
  `docker exec` into the Postgres container yields a passwordless superuser
  shell regardless of which OS user launched it).

**Accepted costs.** This converts *ambient reach* (any process holding the
env var can do real damage) into an *attack-shaped action* (`docker exec` on
a single-user host still yields a superuser shell — this doesn't prevent
that, and isn't claimed to; detecting that class of access is separate,
not-yet-shipped tripwire work). Roles are cluster-global, not per-database:
the migration refuses to run if a same-named, differently-stamped role
already exists, so two Chuvar databases can never silently collide on
credentials — but this pushes a one-time manual provisioning step (setting
each role's login password) onto every deployment; the roles arrive unusable
by design rather than defaulting to something that "just works" insecurely.

**Status:** standing.

---

## 2026-08-07 — Credentials come from files, not the environment

**Every required credential is read from a `0600` file via a `<KEY>_FILE`
convention, in preference to a same-named environment variable.**

**Context.** An environment variable is readable via `/proc` by anything
running as the same OS user, is inherited by every child process, and can
turn up in crash dumps. A file read once at process boot is narrower on all
three counts, and matches how systemd, Docker, and Kubernetes already expect
secrets to arrive. `config.Secret` now prefers `<KEY>_FILE` (refused if
group- or other-readable) over plain `<KEY>` for `DATABASE_URL`,
`CHUVAR_API_TOKEN`, and `REVIEWER_BOOTSTRAP_TOKEN`.

**Rejected alternatives.** Not recorded as a distinct considered option in
the source material beyond "keep using plain env vars" — rejected for the
reasons above (ambient, inheritable, crash-dump-visible).

**Accepted costs.** Plain `<KEY>=` still works for local development, which
means the weaker path remains available and isn't removed — a deliberate
trade of rigor for onboarding friction at dev-loop scale. The Postgres owner
password specifically still has a checked-in fallback
(`${CHUVAR_DB_PASSWORD:-chuvar_dev_only}` in `docker-compose.yml`) that is
explicitly *not* treated as a secret — it exists so a fresh clone runs with
zero setup, on the understanding that anyone relying on it in a real
deployment has skipped a required step.

**Status:** standing.

---

## 2026-08-02 — Launch topology: exactly one binary migrates

**`cmd/migrate` is the only binary that holds schema-DDL authority. Every
other service — `apiserver`, and especially `mcpserver`, which runs inside an
agent's own process tree — verifies the schema on boot and refuses to start
if it's behind, but never applies a migration itself.**

**Context.** `mcpserver` originally could migrate the schema it ran against.
An agent-side process silently applying DDL is how a migration ends up run
by whoever happened to launch a tool first, with no operator in the loop and
no clear record of who did it. Splitting migration authority out entirely
means the least-trusted of the project's binaries (the one launched by an
agent host) can't alter the shape of the database it reads and writes, only
refuse to run against a stale one.

**Rejected alternatives.** Not recorded as a distinct considered option
beyond the prior status quo (any service migrates its own schema on boot) —
rejected for the reason above.

**Accepted costs.** A fresh deployment requires an explicit operator step
(`go run ./cmd/migrate`) before anything else will start; there's no
"first service up just handles it" convenience anymore. This is treated as
the correct trade, not a gap.

**Status:** standing.

---

## 2026-08-01 — Trust boundary: the process boundary, rooted in a human-present unlock

**The enforcement boundary is the process boundary of Chuvar's own services,
rooted in a human-present custody-unlock ceremony — not the REST API alone,
and not an OS-user split. The database sits *inside* that boundary: reaching
it directly from agent context is by definition an attack, not a supported
path.**

**Context.** This resolves the project's own "state the threat model" gap.
The load-bearing distinction is between **ambient reach** — authority
exercisable through a legitimate, discoverable interface (a readable env
var, a checked-in secret, an open port) — which must be zero, and
**attack-shaped actions** — `docker exec` into the DB container, reading
`pgdata` bytes directly, ptracing a daemon — which are not something a
well-behaved agent spontaneously does, are refusable by an aligned one, and
are the correct target for tripwires rather than prevention. Locally, the
adversary is an instruction-following agent that is confused, prompt-
injected, or simply over-diligent, running as the operator's own OS user,
plus commodity exfiltration malware; in a hosted/cloud deployment the bar
rises to a sophisticated targeted attacker, and the design must not foreclose
defending against that harder case later.

**Rejected alternatives.**
- *OS-user separation* — rejected: policy-fragile on Linux, the wrong tool on
  macOS, and hollow under Docker (the `docker` group is root-equivalent, and
  `docker exec` into the Postgres container yields a passwordless superuser
  shell regardless of OS user).
- *Credential custody alone as sufficient* — rejected: Postgres's own
  on-disk data lives under the same OS user as everything else, so
  restricting who *holds a connection string* doesn't address someone
  reading the database's raw files off disk. This is what forced the
  sealed-at-rest commitment below rather than stopping at role-based access.

**Accepted costs.** Tripwires are fail-closed by design: a detected
attack-shaped action means an outage — zeroize data-keys, seal, halt,
require human re-unlock — never just a log line, which means legitimate
operators can be locked out by a false positive and must accept that
trade. As of this decision, `mcpserver` still holds a live `DATABASE_URL`
inside the agent's own process tree (removing that dependency is separate,
not-yet-shipped work) — stated here explicitly as **debt, not precedent**:
no new root of trust may be added to any agent-reachable environment on the
strength of this one being tolerated.

**Status:** standing; the boundary is *stated*, not yet fully *enforced* —
the zero-ambient-authority floor (DB credential fully out of agent reach,
custody-held secrets) is still landing incrementally.

---

## 2026-08-01 — Sealed vault committed: ciphertext at rest, local and cloud

**Fact content, embeddings, and staged diffs are committed to being
ciphertext at rest, in both self-hosted and hosted deployments. The consent
plane — grants, scopes, audit log — stays plaintext, because it has to
remain directly SQL-enforceable.**

**Context.** Chuvar asks users to centralise exactly the kind of personal and
organisational knowledge a data thief wants; that centralisation obliges an
at-rest posture that beats the scattered status quo it replaces, not merely
matches it. Two concrete findings closed off the middle ground of "encrypt
the fact text, leave the embedding vectors plaintext": (1) short, atomic,
self-contained facts — exactly Chuvar's shape — are close to the worst case
for embedding-inversion attacks (the vec2text family), especially against an
embedding model an attacker can obtain and train against; (2) the lexical
search column (`content_tsv`) is a Postgres generated column derived from
the plaintext content, so encrypting the text breaks keyword search outright
regardless, which already forces a retrieval-engine rework. Once that
rework is unavoidable, the real choice was plaintext-at-rest vs.
sealed-at-rest, and sealed won.

**Rejected alternatives.**
- *Encrypt fact text only, leave embedding vectors in plaintext* — rejected
  per the inversion-attack finding above; a plaintext vector for a short,
  atomic fact is not meaningfully less exposed than the plaintext fact
  itself.
- *Leave everything plaintext, rely on access control alone* — rejected as
  inconsistent with the centralisation-obliges-protection reasoning above
  and with the trust-boundary decision the same day.

**Accepted costs.** Retrieval (vector scan, lexical index, RRF fusion) has to
move into service memory behind the unlock ceremony rather than staying
declarative SQL — verified feasible on the actual target hardware (a
Raspberry Pi–class ARM host) at up to roughly 100k facts before an
in-memory flat scan needs anything fancier. The scope-filter-before-ranking
security invariant has to be re-implemented in that in-memory path rather
than relying on a `WHERE` clause, which is restated explicitly rather than
assumed to carry over. This was sequenced deliberately *before* the real
embedding model ships (only a stub embedder exists at decision time), so no
plaintext-vector debt is ever created in the first place — the harder
version of this migration (redacting an existing plaintext corpus) is
avoided by timing, not solved.

**Status:** standing; design commitment made, implementation (ticket-tracked)
in progress as of this log's migration date.

---

## 2026-07-30 — TOTP is an interim second factor, not the final answer

**Approval-granting mutations (approving a grant request, creating a grant
directly, approving a staged diff, renewing a grant) require a device-local
TOTP code on top of the bearer token — explicitly as a stopgap, not a
replacement for per-reviewer hardware-backed authentication.**

**Context.** A bearer token alone is readable by anything with shell access
to the environment holding it, including a compromised or over-diligent
agent session — TOTP adds a factor a compromised session cannot itself
produce. The enrollment gate is designed to be permanently closable rather
than silently reopenable: the count of enrolled devices includes *revoked*
rows, so an attacker who can revoke a device cannot reopen the gate that
way, and there is deliberately no API path to reset it — only a documented,
non-audited break-glass database procedure for the case where every
enrolled device is genuinely lost.

**Rejected alternatives.** Not recorded as a distinct considered option
beyond "keep the single shared bearer token as the only gate" (already
addressed by the 2026-07-26 per-reviewer-tokens decision below) — TOTP was
added as the next layer on top of that, not a replacement for it.

**Accepted costs — stated honestly as a stopgap.** An earlier version of
this feature's documentation claimed a factor "a shell-access attacker alone
cannot produce" while the TOTP secret itself sat plaintext one loopback
database connection away — that was an aspirational security claim ahead of
what the mechanism actually delivered, corrected once flagged. TOTP secrets
are now sealed at rest under a custody-held key (landed 2026-08-02), but the
underlying gap this stopgap exists to eventually close — real per-reviewer
hardware-backed authentication (WebAuthn/passkeys) — remains open. This
entry records both what TOTP buys and the bar it does *not* meet. It raises
the cost of a stolen bearer token: once any device is enrolled, the token
alone can no longer mint a new reviewer credential and self-enrol. But it is
still a shared-secret code, not a possession- or biometric-backed factor —
and revoking a device never reopens the enrollment gate, because revoked
rows still count toward "ever enrolled", precisely so an attacker who
revokes real devices cannot reopen it that way.

**Status:** standing as an interim stopgap; superseded when WebAuthn/passkey
reviewer authentication ships (tracked, not yet landed as of this log's
migration date).

---

## 2026-07-27 — Signing requirement is repo policy; unsigned proceeds emit an exception record, not an authorization

**Whether commit signing is required is a human-set, calm-time repository
policy (`required` / `preferred` / `off`) — never a runtime grant an agent
can request. When the signing backend is unreachable under `preferred`,
proceeding unsigned writes a local, later-reconciled exception record; it is
never authorized in the moment.**

**Context.** This followed directly from rejecting a specific earlier
proposal (below). Repo policy moves the decision of "is unsigned ever
acceptable here" from mid-session, under time pressure, made by whoever is
tired, to a deliberate choice made calm and in advance. Under `required`
there is no live mechanism to proceed unsigned at all — the agent blocks and
the work waits.

**Rejected alternatives.**
- ***A `git.sign.bypass` grant** — scoped, time-boxed, audited, revocable,
  exactly like every other grant in the system — proposed and then rejected
  the same day. It fails on three counts: (1) a broker-issued bypass cannot
  cover the case where the broker itself is unavailable, which is precisely
  the scenario that motivates wanting a bypass in the first place — the
  mechanism is structurally absent exactly when it would be needed; (2) it
  is an attractive nuisance — an agent under pressure requests it, a human
  under pressure approves it, and an emergency escape hatch quietly becomes
  a supported feature; (3) it launders the signal — today an unsigned commit
  means something broke and a human should look at it, but as a *granted*
  bypass, unsigned commits would read as intentional and authorized, and
  nobody would investigate. That is a net loss of observability, the
  opposite of the goal.

**Accepted costs.** Under `preferred`, the system relies on the exception
record actually being produced and actually being reconciled later — it is
an audit artifact, not a live control, and (unlike a real grant) there is no
enforcement preventing an agent from proceeding unsigned and simply failing
to write the record honestly. This is accepted because it is still strictly
better than the alternative it replaces: it degrades to *legible* absence of
a control rather than to a disguised one.

**Status:** standing.

---

## 2026-07-26 — Per-reviewer device tokens replace the shared bearer secret

**Approval-side authentication moved from a single shared bearer token to
individually issued, individually revocable per-reviewer device tokens.**

**Context.** A single shared secret means every approval action is
attributable only to "whoever had the token," which doesn't hold up against
this project's own principle that actor identity must derive from an
authenticated credential, not a claim in a request body. Per-device tokens
make `decided_by`/`approved_by`/`revoked_by` mean something real, and make
losing one device a narrow, individually-revocable event instead of a
whole-system secret rotation.

**Rejected alternatives.** Not recorded as a distinct considered option
beyond the prior status quo (one shared bearer secret for all approval
calls) — rejected for the reason above.

**Accepted costs.** This is the layer the 2026-07-30 TOTP decision above
builds on top of, not a complete answer on its own — a stolen device token
is still just a bearer credential until the second factor lands.

**Status:** standing.

---

## 2026-07-25 — sqlc over an ORM for the store package

**Hand-written SQL, typed via [sqlc](https://sqlc.dev) code generation, not
an ORM (`ent`, `gorm`, etc.) — landed as a pure internal swap with no public
API change.**

**Context.** Raw SQL strings scattered through the store package had been
flagged as a maintainability smell. The migration to sqlc was deliberately
scoped so that `Store`'s public method signatures and hand-written Go types
never changed — nothing downstream needed touching — which is also why it
landed as a standalone PR appended after the rest of a stacked series rather
than threaded through it: a pure implementation swap creates no rebase
dependency on anything else.

**Rejected alternatives.**
- *An ORM (ent/gorm-class tool)* — rejected specifically to keep hand-tuned,
  performance- and security-sensitive queries under direct control: the RRF
  hybrid-retrieval fusion query and the scope-visibility CTEs (which
  implement the "filter before rank" security invariant) are exactly the
  kind of query an ORM's abstraction layer tends to fight rather than help
  with.

**Accepted costs.** sqlc analyzes queries against a live database rather
than parsing schema statically, because its static parser doesn't understand
pgvector's `vector` type or the `<=>` operator (they come from the
extension, not core Postgres) — so regenerating code requires a running,
migrated Postgres instance, not just a checkout of the repo.

**Status:** standing.

---

## Jul 2026 — Naming: "Chuvar" replaces the working title "Memory Vault"

**The project's name is Chuvar.** The repo, Go module path, and all forward
documentation were renamed from the "Memory Vault" working title used during
early design and the first build.

**Context.** "Memory Vault" was always a placeholder used to get design work
started; once a real name was chosen it was front-loaded through the history
rebuild that was already underway for review reasons — the rebuilt commits
carry the final name in their content rather than being renamed in a
dedicated follow-up change, and the standalone rename PR that had been
planned turned out to have nothing left to do. References to "Memory Vault"
that survive in older commit messages and early design material are
deliberately left alone as historical context.

**Rejected alternatives.** Not recorded — this entry records the rename
itself (what changed and when), not a naming-options bake-off.

**Accepted costs.** Early design documentation written before the rename
still refers to "Memory Vault"; that's treated as historical context to
leave alone; not a naming inconsistency to hunt down and fix retroactively.

**Status:** standing.

---

## Jul 2026 — License: Apache-2.0, whole repo, unrestricted, forever

**The entire project is Apache-2.0 licensed — no gated `ee/` directory, no
separate private companion repo, no time-limited or revenue-threshold
clause.**

**Context.** Decided by walking through recent precedent rather than
first-principles license theory: Temporal reached a multi-billion-dollar
valuation on a permissive license, with hosted-cloud revenue doing the
earning, in the same era that Redis's move to a source-available,
usage-restrictive license drove every major hyperscaler to Valkey — a
community-governed fork with no commercial relationship back to Redis. The
restrictive license didn't protect the revenue it was meant to protect; it
handed the distribution channel to a fork. Chuvar's shape — an opinionated
product, not a generic infrastructure primitive like a cache or a search
index — was judged closer to the Temporal precedent, which was the deciding
factor over a stronger-but-probably-unnecessary copyleft-style license. The revenue plan that follows from this, in likely
order: hosted SaaS first, support contracts second, enterprise-only features
only once real demand from (1) or (2) names one — nothing in the free
edition is deliberately withheld today.

**Rejected alternatives.**
- *AGPL or a source-available "strip-mining protection" license* — rejected
  per the precedent reasoning above.
- *A split repo (public core + private/gated enterprise directory)* —
  rejected on "trust is core, and there's nothing to hide under this license
  model anyway"; also rejected as complexity to pay for speculatively, ahead
  of any customer need that would justify it.

**Accepted costs.** No enterprise-tier revenue lever exists yet, and none
is being built ahead of a real, demonstrated need for one — meaning the
project accepts near-term revenue optionality it does not currently need
in exchange for not building and maintaining speculative gated
infrastructure.

**Status:** standing.

---

## Jul 2026 — Postgres + pgvector as the sole source of truth (Community Edition)

**Facts, scope tags, grants, audit log, and embeddings all live in one
transactionally-consistent Postgres database. No external vector database
(Pinecone, Qdrant, etc.) is a dependency of the Community Edition's source of
truth. Retrieval is hybrid: `tsvector` keyword search fused with pgvector
cosine similarity via Reciprocal Rank Fusion (RRF), implemented in SQL.**

**Context.** Every core operation here — "everything readable under grant
G," a complete audit trail, clean revocation — is deterministic and
relational; fighting an approximate-nearest-neighbor-first engine to
recover exactness would be working against the tool. Embeddings are also
lossy, model-specific, and go stale whenever the embedding model changes,
while canonical text and metadata are portable indefinitely — the dependency
direction has to point from text to vectors, never the reverse, and a
pluggable external vector store as the source of truth would invert that.
At the actual scale in play (thousands to low tens of thousands of personal
facts, not hundreds of millions of records), exact cosine similarity over
the full set costs single-digit milliseconds — the scale that would justify
a dedicated vector database doesn't exist here. Community Edition also
cannot carry a hard dependency on someone else's proprietary managed cloud
without contradicting both the open-core model and the project's own
data-portability pitch. Critically, **scope filtering happens in the SQL
`WHERE` clause before similarity ranking** — this is a security property
(an ungranted fact must never enter the candidate set at all), not merely a
performance choice, and a specifically-examined competitor codebase's
external-vector-store escape hatch was found to regress exactly this
property (filter-after-rank instead of filter-before-rank) — direct evidence
for holding this line rather than a hypothetical risk.

**Rejected alternatives.**
- *A dedicated vector database (e.g. Pinecone) as source of truth* —
  rejected per the exactness, portability, scale-mismatch, and open-core
  reasoning above. Remains available only as an optional, pluggable
  `RetrievalBackend` implementation behind an interface, not a CE
  dependency.
- *ParadeDB / `pg_search` (BM25 via Tantivy inside Postgres)* — investigated
  and explicitly not adopted, for now: BM25's real advantages (inverse
  document frequency, document-length normalization) matter most on large,
  heterogeneous documents, whereas this corpus is thousands of short,
  fairly uniform, already-paraphrased facts, where plain `tsvector` plus
  vector similarity already covers the exact-term-vs-paraphrase split
  reasonably well; it is also a compiled Postgres extension requiring a
  blessed image or Helm chart, which cuts against "Community Edition runs on
  any Postgres"; managed-platform support for it was also observed to be
  inconsistent. A lighter-weight BM25 option is on the list to revisit only
  if a real corpus ever demonstrates retrieval quality, rather than fact
  quality, is the actual bottleneck.

**Accepted costs.** Retrieval logic lives as roughly a hundred lines of
hand-tuned SQL rather than behind a mature dedicated search product's query
language — accepted as the right trade at this project's scale and audit
requirements, revisited only if evidence says otherwise.

**Status:** standing.

---

## Jul 2026 — No direct writes: the staged-diff approval gate is the core differentiator

**The system exposes no deterministic write endpoint for memory. Every
proposed fact is staged as a diff and requires explicit human approval
before it commits to the canonical store.**

**Context.** A competitive survey of comparable memory-storage projects
found this gate has no real precedent in the space: every comparable system
examined commits proposed memory synchronously and deterministically, with
at most automatic merge/dedupe logic and no human-review checkpoint for a
contradictory or suspicious write. This is treated as the project's actual
wedge — not an implementation detail that happens to differ, but the reason
the project exists as something other than "another memory store." Painless
review is correspondingly treated as a first-class feature rather than a
checkbox, since it's the primary defense against a poisoned or manipulative
write actually being approved.

**Rejected alternatives.** *Direct, deterministic writes with automatic
merge/dedupe/conflict-resolution logic (the pattern every surveyed
comparable project uses)* — rejected as the default industry pattern this
project deliberately does not follow, for the reason above.

**Accepted costs.** Every write path is slower by construction — nothing
lands without a human approval step, which is a real throughput cost the
project accepts as the point, not a rough edge to be optimized away.

**Status:** standing.

---

## Jul 2026 — Bouncer pipeline built behind interfaces; Temporal deferred

**The write pipeline (`ingest → classify → dedupe → stage → approve →
commit`) is real, running code from the start — implemented as a plain Go
state machine over staged diffs, with `Classifier` and `Embedder` as
interfaces backed by naive/deterministic stub implementations. Temporal is
the intended long-term workflow engine for this pipeline but is deliberately
not stood up yet.**

**Context.** `Classifier` and `Embedder` are interfaces rather than bare
functions because a second, real implementation (a hosted model in
production; a tiny in-memory model was also used for prototyping) was
already known to be coming — this is the "the second caller is already
decided" bar for introducing an interface, not speculative abstraction
introduced just in case.

**Rejected alternatives.** *Standing up a real Temporal cluster for early
work* — rejected as premature for the stage the project was at; noted as an
explicit two-way door, deliberately left open rather than closed off, to be
revisited rather than built ahead of need.

**Accepted costs.** The bouncer's classify and dedupe steps run on stub
logic, not a real model, until that door is deliberately opened — an
explicit, documented placeholder rather than a hidden gap.

**Status:** standing; Temporal adoption and a real embedding provider remain
open, tracked, two-way doors — not yet exercised as of this log's migration
date.
