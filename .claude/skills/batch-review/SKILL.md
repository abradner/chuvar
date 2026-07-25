---
name: batch-review
description: Chuvar's batch PR shipping workflow - fan out a body of work as a stack of small atomic single-commit PRs (interstitials, from base to cap), let CI and the review bots (Copilot, Codex) run immediately but treat all feedback as write-only until the whole batch is in, then synthesise the feedback in aggregate, ship all reactive work as ONE followup PR stacked on the cap, resolve interstitial comments as "fixed in the followup" or "not relevant", merge interstitials bottom-up with merge commits and squash-merge the followup last. Use this whenever the user wants to review open PRs holistically or in aggregate, process accumulated bot review comments across several PRs, ship a "review feedback batch" or followup PR, or mentions their overnight/fired-off batch of work - even if they don't say "batch review" explicitly. ALSO use at fan-out time - when the user asks to build a planned body of work as small/carefully-factored/stacked PRs, or hands off a stack before signing off ("trust your judgement", "crashing out now") - the fan-out discipline (never react to feedback mid-stack) is what makes the rest of the workflow cheap.
---

# Batch Review (Chuvar)

A workflow for shipping a large body of work as many small PRs without
drowning in drip-fed review cycles. Each PR is the GitHub mechanism for
getting per-unit CI and review on one slice of a bigger body of work. The
core bargain: **feedback is write-only until the whole batch is
synthesised**. CI and the bots run immediately on every PR, comments
accumulate freely — but nothing responds to them and no reviewed branch is
rewritten. All reactive work lands once, in a single followup PR, and the
stack merges bottom-up.

## Terminology

- **Interstitial** — any PR in the proactive stack, bottom to top inclusive.
  Exactly **one commit** each: the merge commit that lands it wraps exactly
  the reviewed change. (A contingency merge-of-main commit is the tolerated
  exception.)
- **Base** — the bottom interstitial; the one whose PR targets main.
- **Cap** — the top interstitial; the end of the proactive work.
  Topologically the tip during fan-out, but *not* the reactive surface —
  don't call it the head.
- **Followup** — the reactive PR, created only after synthesis, stacked on
  the cap. All reactive work happens here: holistic-review findings plus
  every interstitial comment assessed as having merit. May be **N commits**;
  it is **squash-and-merged** (nothing ever stacks on it, so its history is
  free to be messy). The followup is the batch's only live-feedback surface
  and its release gate.

Why the workflow works:
- Small atomic single-commit interstitials keep the review bots focused on
  detail instead of getting lost in a diverse changeset — and let a human operator hold
  the whole batch in their head.
- Opening everything ready-for-review means CI starts instantly and the
  feedback window is fully open from minute one.
- Not reacting mid-stack means main never moves underneath the stack because
  of the batch itself, review comments stay anchored to real SHAs, and no PR
  gets superseded by its own feedback loop (the classic failure: piecemeal
  fix batches merge to main and hollow out a still-open PR).
- Fixing only in the followup, then merging bottom-up, avoids conflicts,
  restacking, and rebase drama entirely.

## Repo specifics

- **Review bots**: Copilot (`copilot-pull-request-reviewer`, inline +
  "suppressed due to low confidence" comments hidden in `<details>` blocks —
  read them, they're often good) and Codex (`chatgpt-codex-connector`;
  subject to usage limits, may post only a limits notice — treat that as "no
  review", not a clean bill).
- **Stack topology gotcha (learned the hard way)**: the base must target
  `main`, and when a stacked PR merges into its parent *branch* rather than
  main, its commits never reach main — check `gh pr list` base refs before
  assuming the stack lands anywhere. Merging a PR whose base branch's own PR
  already merged is the specific trap (this repo's PR #4).
- **Backend validation** (from `backend/`): Postgres up first
  (`sudo -n docker compose up -d` — Docker needs elevated access in this
  sandbox, AGENTS.md §4.5; port 54322, and on the dev box the main
  checkout's container may already hold the port — reuse it). Then
  `DATABASE_URL=postgres://chuvar:chuvar_dev_only@127.0.0.1:54322/chuvar?sslmode=disable mise exec -- go test -p 1 ./...`
  — **`-p 1` is mandatory** (shared-database test isolation, AGENTS.md §4)
  — plus `mise exec -- go vet ./...`.
- **sqlc drift check**: after any change under
  `backend/internal/store/queries/`, regenerate with `DATABASE_URL` set
  (`mise exec -- sqlc generate` from `backend/`) and confirm
  `git status internal/store/sqlcgen/` is clean; sqlc analyzes against the
  live DB because of pgvector types.
- **Frontend validation** (from `frontend/`): `mise exec -- bun install`
  then `mise exec -- bun run test`.
- **Conventions the bots correctly police** (verify the citation, then act):
  - AGENTS.md §3.1: no direct writes to `facts` — only `store.CommitDiff`,
    behind human approval.
  - AGENTS.md §3.2: scope-filter in the `WHERE` clause **before** ranking in
    every retrieval path (search *and* dedupe) — a security property.
  - AGENTS.md §6 review discipline: trust-boundary questions ("who is the
    caller, how do we know, what if they lie?"), secure-by-default network
    settings (loopback bind, no CORS wildcard, timeouts actually wired),
    closed-vocabulary validation at input boundaries, and
    regression-tested fixes (seen to fail, then pass).
- **Followup naming precedent**: `fix: PR stack #A–#B review feedback`.
- **Deferral ledger**: product-decision-level findings go in a GitHub issue
  (see #12 for the shape); the followup PR body carries the
  actioned / not-actioned triage for the batch itself.

## Phase 0 — Fan-out (creating the batch)

- Split into small, atomic, **single-commit** interstitials. Stack them
  (branch off the parent, PR based on the parent branch); the base targets
  main.
- **Open every PR ready-for-review immediately** — CI and the single bot
  review round start at once; the feedback window is open for the whole
  bake.
- Each PR body states: summary, how it was validated — **and ends with the
  standard Batch block**. The description travels with the PR into every
  reviewer's and every fresh session's context, so this block is the layer
  that works even when the skill doesn't trigger and AGENTS.md goes unread:

  The block only ever states what is known at write time — **never guess
  ordinals, totals, or future PR numbers, and never leave `<placeholders>`
  in a live description**. At creation that means:

  ```markdown
  ## Batch
  - **Batch**: <short-slug>
  - **Position**: base | interstitial (roster stamped when the cap opens)
  - **Stacked on**: #<parent> (base: main)
  - **Feedback policy**: write-only until synthesis — comments here are
    harvested and answered in the followup PR. Author-side agents: do not
    push fixes to this branch (see `.claude/skills/batch-review`).
    Reviewers: review fully as normal; unanswered comments are the
    workflow, not neglect.
  - **CI policy**: interstitial red is acceptable when explained by the
    stack; the followup PR is the release gate.
  - **Merge policy**: operator-initiated only — no agent merges any
    batch PR without an explicit go-ahead from the human operator.
  ```

- **Roster sweep — fan-out is not complete until this is done.** When the
  cap opens, one pass over every batch PR stamps the now-known facts: the
  Batch line gains the roster (`<short-slug> (#<first>–#<last>)`) and
  Position becomes `base (1/<m>)`, `interstitial (<n>/<m>)`, or
  `cap (<m>/<m>)`. This also fixes the PR list the phase-transition monitor
  watches.
- From this moment, the discipline is **no reaction**: don't reply to
  comments, don't push fixes to reviewed branches, don't merge main into the
  stack because of batch feedback. Comments are annotations to harvest
  later.

## Phase 1 — Bake (and contingency housekeeping)

Normally there is nothing to do here — the stack sits still while CI and
reviews land. Two contingencies:

- **Main moved for unrelated reasons** (another work stream merged): merge
  main into affected branches — never rebase a branch with review context;
  rebasing orphans review threads. Before resolving conflicts, find the
  branch's true payload with `git log HEAD --not origin/main --oneline`;
  stacked branches carry stale copies of parent work, and those hunks take
  main's side. After committing, audit `git diff origin/main...HEAD --stat`
  — the effective diff is the truth of what the PR still changes, and how
  you catch a superseded PR or a hunk silently reverting other work. Run
  the full backend suite (`-p 1`, with `DATABASE_URL`) — clean merges still
  conflict semantically (e.g. a schema/primary-key change under new
  queries).
- **A genuine showstopper lands in review.** For interstitials the bar is
  **irreversible-on-merge harm**: a destructive migration or backfill that
  destroys data the moment the stack lands (no followup can undo it). This
  repo has no CD, so nothing deploys from an interstitial — security
  findings, red CI, and correctness bugs all wait for the followup, which
  merges minutes later.

  If a fix commit does get injected into an interstitial, that *potentially*
  triggers a restack — but evaluate at the time rather than restacking
  reflexively: with merge-commit semantics the fix usually reunifies on its
  own. Propagate upward only when a child actually conflicts with the fix,
  needs it for its own CI to be meaningful, or the followup builds on it.

**Interstitial CI red is acceptable** when the stack explains it; only the
followup PR's CI is the release gate. An *unexplained* red is a real
signal, not noise.

**Event-driven nudges (webhooks, CI toggles, monitors).** Per-PR
"auto fix / address CI comments" toggles inject per-PR-scoped prompts that
cannot see the stack. If used at all, enable them **only on the followup
PR**. Any mid-batch event is a **ledger entry, not a work order**: triage
against the interstitial showstopper bar, record for synthesis, stand down.

## Driving phase transitions (don't poll, don't guess)

- **Fan-out → synthesis**: after the cap opens, arm a monitor that fires
  when every interstitial has a concluded CI run and at least one automated
  review, with a ~30-minute fallback in case a reviewer goes silent.
- **Followup reactivity**: watch the followup PR from the orchestrating
  session (comment + CI poll with the showstopper filter).
- **Followup green → merge**: when the followup's CI concludes green and
  its threads are resolved, wake once more to report that the stack is
  ready and ask for the go-ahead — never to start merging (see the Phase 4
  gate). The merge train itself only runs on the operator's explicit
  say-so.

## Phase 2 — Synthesis (aggregate review + feedback harvest)

When the batch is fully reviewed, do one synthesis pass over the whole body
of work. Deliverable: a per-PR verdict plus batch-level findings, written
for the human.

Harvest **all** comments across the stack:
- Issue comments: `gh pr view N --json comments`
- Review bodies: `gh api repos/abradner/chuvar/pulls/N/reviews`
- Inline comments: `gh api repos/abradner/chuvar/pulls/N/comments` — this
  is where the bots put the substance, including Copilot's suppressed
  low-confidence comments.

Add your own aggregate review — the things per-PR reviewers structurally
miss: cross-PR interactions, sibling inconsistency (the same class of
problem solved two ways), gaps *adjacent* to a PR's purpose, and — for this
repo specifically — the AGENTS.md §6 trust-boundary questions applied
across the whole surface, not per file.

Triage everything on merit, remembering reviewers only had per-PR context:
- Comments citing AGENTS.md conventions are usually right — verify the
  citation, then act.
- Claims about runtime behavior: verify against the actual code — only fix
  what you can trace or reproduce.
- Comments re-litigating deliberate design (documented in code comments or
  AGENTS.md), or already answered by a later interstitial: mark
  not-relevant with a one-line reason.

## Phase 3 — The followup PR

Ship the synthesis as **one followup PR stacked on the cap** (it retargets
automatically as parents merge; it may be N commits — it squash-merges):

- Every actioned item grouped by source PR, with reviewer/severity noted.
- A body section for comments **assessed and not actioned**, with reasons —
  this keeps the write-only bargain honest.
- One full validation pass: backend suite (`-p 1`, `DATABASE_URL` set),
  `go vet`, sqlc drift check, frontend tests — not per-comment validation.
- Its Batch block reads: `Position: followup — live feedback surface and
  release gate; must be robust and green before the stack merges;
  squash-and-merge.`

Then resolve every interstitial comment thread: reply "fixed in the
followup (#<followup>)" or "not relevant: <one line>". This is the only
time the batch touches its own review threads — and since it visits every
interstitial anyway, the same pass appends `- **Followup**: #<followup>`
to each Batch block.

## Phase 4 — Merge the stack

**Gate: never start this phase without the human operator explicitly
saying to merge now** — a synthesis pass, a green followup, or an "auto
mode" session
default is not that signal. This applies even when the rest of the batch
workflow is running autonomously: pushing merge commits and deleting
remote branches is exactly the kind of hard-to-reverse, shared-state
action that needs a live go-ahead each time, not standing authorization
from having approved the workflow once. If the stack is ready, say so and
stop — don't proceed into merging on your own initiative.

Once given the go-ahead: merge interstitials bottom-up (base first),
**plain merge commits** — no squash, no rebase; each merge commit wraps
exactly one reviewed commit.

**Retarget each child before deleting its parent's branch — don't rely on
`--delete-branch` to do both atomically.** GitHub auto-retargets an open PR
when its base branch merges, but that retarget is not guaranteed to have
landed before a same-command branch deletion completes — deleting the base
branch out from under a not-yet-retargeted PR closes it (this happened in
this repo's own #5→#6 merge: `gh pr merge 5 --delete-branch` closed #6
because `pr/05-store` vanished before GitHub retargeted #6 to main). Per
interstitial, in this order:
1. `gh pr merge <n> --merge` (no `--delete-branch`).
2. Confirm the next PR's base is now `main` — retarget explicitly if not
   (`gh api -X PATCH repos/abradner/chuvar/pulls/<next> -f base=main`).
3. Only then delete the just-merged branch.

If a child PR does end up closed by a premature delete: push the branch
back from its last known SHA, reopen the PR (`gh api -X PATCH
.../pulls/<n> -f state=open`), retarget to main, then delete the branch
again. No work is lost — the commits are still reachable from the SHA —
but confirm state before continuing the train.

Merge rapidly and consecutively — interstitial CI red doesn't block when
the stack explains it. The followup merges last, **squash-and-merge**,
carrying all the reactive work.

## Rules of thumb

- Feedback is write-only until synthesis. No replies, no mid-stack pushes.
- One review round per PR; the followup is the only live-feedback surface.
- Interstitials: one commit each, merge-committed. Followup: N commits,
  squash-merged, release gate.
- Merge main into a batch branch only when the world moved for reasons
  outside the batch — and then: `git log HEAD --not origin/main` first,
  effective-diff audit + full `-p 1` suite after.
- Reactive work lands in the followup. Interstitial threads get "fixed in
  the followup" or "not relevant", never code pushes.
- Merge bottom-up, rapidly and consecutively. Never rebase a reviewed
  branch. Retarget each child to main before deleting its parent's branch —
  don't let `--delete-branch` race GitHub's auto-retarget.
- Phase 4 needs an explicit, per-batch go-ahead from the human operator — never
  self-initiate the merge train, including under autonomous/auto-mode
  operation.
- Only the followup's CI gates the batch. Interstitial red is fine when the
  stack explains it; unexplained red is a real signal.
- The interstitial showstopper bar is irreversible-on-merge harm — nothing
  else (no CD here). The followup's bar is broader (it's the release gate).
- Defer everything that isn't a showstopper, and write the deferral down —
  the followup PR body is the audit trail: actioned, deferred, rejected,
  each with a reason; product-decision deferrals graduate to an issue.
