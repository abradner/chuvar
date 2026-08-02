---
name: batch-review
description: Batch PR shipping workflow - fan out a large body of work as a stack of small atomic single-commit PRs (interstitials, from base to cap), let CI and the review bots (Codex, Copilot) run immediately but treat all feedback as write-only until the whole batch is in, then synthesise the feedback in aggregate, ship all reactive work as ONE followup PR stacked on the cap, resolve interstitial comments as "fixed in the followup" or "not relevant", merge interstitials bottom-up and squash-merge the followup last. Use this whenever the user wants to review open PRs holistically or in aggregate, process accumulated bot review comments across several PRs, ship a "review feedback batch" or followup PR, or mentions their overnight/fired-off batch of work - even if they don't say "batch review" explicitly. ALSO use at fan-out time - when the user asks to build a planned body of work as small/carefully-factored/stacked PRs, or hands off a stack before signing off ("trust your judgement", "crashing out now", "before bed") - the fan-out discipline (never react to feedback mid-stack) is what makes the rest of the workflow cheap. This is a deliberately different, opt-in mode for a genuine multi-PR fan-out, not this repo's default single-PR flow.
---

# Batch Review

Ship a large body of work as many small PRs without drowning in drip-fed
review cycles.

**The bargain: feedback is write-only until the whole batch is synthesised.**
CI and bots run on every PR from the moment it opens. Nothing answers them.
No reviewed branch is rewritten. All reactive work lands once, in a single
followup PR.

**Opt-in, not the default.** The default here is one PR, react immediately,
merge when green — still correct for single-PR or small-stacked work. Reach
for this skill when the body of work wants many small PRs in flight at once
and reacting per-PR would mean drowning in drip-fed review cycles. A batch
can be run deliberately on a smaller change to exercise the workflow, but
that is a choice, not the trigger.

## Terminology

| Term | Meaning |
|---|---|
| **Interstitial** | Any PR in the proactive stack. **Exactly one commit.** (A contingency merge-of-main is the only tolerated extra.) |
| **Base** | Bottom interstitial. Targets main. |
| **Cap** | Top interstitial. End of proactive work — not the reactive surface. |
| **Stack object** | The platform's stack entity (badge, map, merge button) in the stacked flavour. "The stack" unqualified means the set of interstitial PRs, in either flavour. |
| **Followup** | The reactive PR. Created only after synthesis, stacked on the cap. May be N commits. Squash-merged. The batch's only live-feedback surface and its release gate. |

Worked example: #16–#20 were interstitials, #21 the followup.

## Repo specifics (chuvar)

**Bots**

| Bot | Trigger | Use for |
|---|---|---|
| Copilot (`copilot-pull-request-reviewer`) | Ready-for-review edge (opened ready, or draft→ready). **Never on push.** | Every PR. Per-PR mechanical review. |
| Codex (`chatgpt-codex-connector[bot]`) | `@codex review` only — auto-review is off. Answers on drafts. | Aggregate diffs only. Budget 2–3 per batch. |

- Always ask for **comments only, no commits**. An agent pushing to a batch
  branch breaks the write-only discipline.
- Feedback lands ~5 min after the trigger. Don't look before ~10.
- Always open Copilot's `<details>` "suppressed due to low confidence" block.
  Real bugs hide there under a "no new comments" summary.
- Codex is also usage-limited here and may answer with only a limits notice.
  That is "no review", not a clean bill.

**Validation**

- Postgres first: `sudo -n docker compose up -d` (Docker needs elevated
  access in this sandbox, AGENTS.md §4.5; port 54322, and the main
  checkout's container may already hold it — reuse it).
- Go (from `backend/`), with `DATABASE_URL` built from the *configured*
  password rather than the literal — a checkout with `CHUVAR_DB_PASSWORD` set in
  `.env` uses that, and hardcoding the fallback makes every validation
  connection fail on such a checkout:
  `PW="${CHUVAR_DB_PASSWORD:-chuvar_dev_only}"` (sourcing `.env` first if present),
  then `DATABASE_URL=postgres://chuvar:$PW@127.0.0.1:54322/chuvar?sslmode=disable`:
  `mise exec -- go vet ./...`, `go build ./...`, `go test -p 1 ./...`.
  **`-p 1` is mandatory** — shared-database test isolation, AGENTS.md §4.
- **sqlc drift**: after any change under `backend/internal/store/queries/`,
  regenerate with `DATABASE_URL` set (`mise exec -- sqlc generate`) and
  confirm `git status internal/store/sqlcgen/` is clean. sqlc analyses
  against the live DB because of pgvector types.
- TypeScript (from `frontend/`): `mise exec -- bun install`, `bun run lint`,
  `bun run build` (tsc + vite), `bun run test`.

**CI** — `.github/workflows/ci.yml`, on every PR and push to main. A
`dorny/paths-filter` job splits `backend/` from `frontend/`; the halves run
conditionally.

Two consequences for this workflow:

- **Checks always conclude here.** The filtering is per-*job*, not per-
  workflow: the workflow itself has no `paths:` filter, so it starts on
  every commit and the `changes` job always runs. A phase gate waiting on "a
  concluded CI run" can never hang, and `bin/release-tag` never faces an
  empty check list. (Sibling repos that filter at the workflow level need an
  escape hatch for exactly that; chuvar does not, and adding one would only
  ever mean tagging an unverified main.)
- **A skipped job is not a passing job.** A one-sided PR shows no job for
  the other half, so green means "no failures", not "tested" — and nothing
  announces that. Read *which* jobs ran, not just the colour, before
  treating a green as coverage.

> **Not yet built — do not read as current behaviour.** Planned: skip CI on
> main for interstitials, and always run it in full on the followup
> regardless of paths, which would make the followup's green
> unconditionally meaningful. Today neither half of that exists: CI runs on
> every push to main, and the followup is filtered like any other PR.

**Merge mechanics.** Squash-merging a parent can break its children. Squash
writes a new commit duplicating the parent's payload while the child's merge
base stays pre-batch. Git still recognises identical changes on both sides,
so a child carrying *only* the parent's payload merges cleanly. The conflict
comes from **divergence**: where the child also modified the same hunks, git
has two different versions from an ancestor with neither. Predict conflicts
per overlapping-and-modified hunk, not per shared file.

This repo therefore splits by flavour:

- **Manual flavour: merge-commit the interstitials, base to cap**, then
  squash the followup onto main. Child history stays a true ancestor, so no
  conflict arises from the train itself, and each merge commit wraps exactly
  one reviewed commit. The net effect is still one commit per PR on main.
- **Stacked flavour: "Squash and merge stack"**, which the platform
  sequences itself (see the deltas section). One squash commit per PR,
  bottom-up — the same one-commit-per-PR outcome by a different mechanism.

Under merge commits there is no per-hunk resolution step and propagation of
an injected fix is usually optional (see Phase 4). Both are mandatory under
squash — which is why the manual flavour here does not squash interstitials.

**Other**

- **Stack topology trap**: the base must target `main`. When a stacked PR
  merges into its parent *branch* rather than main, its commits never reach
  main — check `gh pr list` base refs before assuming the stack lands
  anywhere. Merging a PR whose base branch's own PR already merged is the
  specific trap (this repo's PR #4).
- Conventions the bots correctly police, verify then act: AGENTS.md §3.1
  (no direct writes to `facts` — only `store.CommitDiff`, behind human
  approval), §3.2 (scope-filter in the `WHERE` clause **before** ranking, in
  every retrieval path — a security property), §6 (trust-boundary questions,
  secure-by-default network settings, closed-vocabulary validation,
  regression-tested fixes seen to fail first).
- **Deferrals go to a Notion task** in the *Memory Vault Tasks Tracker*
  (AGENTS.md §6 already makes that the team's real view of progress), **with
  its metadata set** — a bare title in the tracker is barely better than a
  PR-body table:

  | Property | Set it to |
  |---|---|
  | Task name | The finding, not the symptom |
  | Status | `Not started` |
  | Impact | `High` / `Medium` / `Low` — a deferred correctness bug is not Low |
  | Effort level | `Small` / `Medium` / `Large` |
  | Format | `🐞 Bug`, `💻 Tech Debt`, `🚧 KTLO`, `🔬 Research/Spike`, … (multi) |
  | Function | usually `Code/Tech`; `Docs/Ops` for tooling and workflow |
  | Project | relate it to the Chuvar project row |

  The body carries the finding, the reasoning, and acceptance criteria.
  **Not a GitHub issue** — an earlier revision of this skill said issue #12
  was the shape to follow; #12 was a one-off, not the convention, and the
  rule was wrong. **Not a PR-body table** either: that goes stale between
  rounds and vanishes on merge.
- Release: `bin/release-tag` cuts a `v<UTC yyyymmddHHMM>` tag at main's tip
  and refuses a main that isn't green. There is **no image build yet**
  (deployment undecided, AGENTS.md §5), so today the tag marks a release
  point and nothing more.
- Followup naming: `fix: PR stack #A–#B review feedback` (#21 precedent).

## Phase 1 — Flavour probe

The workflow has two mechanical flavours. **Policy is identical in both** —
write-only feedback, the Phase 2 self-review, the round cap, aggregate-first
Codex, the showstopper bar, the Phase 7 operator gate. Only the branch/merge
plumbing differs.

**"Manual" means the stack is hand-managed — not that the PRs are
standalone.** Both flavours produce a stack: every interstitial branches off
its parent and its PR targets the parent's branch. In the manual flavour you
create the branches, stamp the roster, and run the merge choreography
yourself; in the stacked flavour the tooling and the platform do it. The
Fallback's "PRs stay open as ordinary PRs" means *without a stack object* —
the branch topology is unchanged. (Single standalone PRs are the repo's
default flow, which this skill is the opt-in alternative to — a third sense
of the word, and not one this document ever uses.)

Probe before creating any branch — capture the failure mode, don't swallow
it, because the decision below depends on *which* way it failed:

```bash
if ! gh stack --help >/dev/null 2>&1; then
  echo "manual (extension missing)"
elif out=$(gh api repos/{owner}/{repo}/stacks 2>&1); then
  echo "stacked"
elif grep -q "HTTP 404" <<<"$out"; then
  echo "manual (repo not enrolled)"
else
  echo "transient probe failure — retry once: $out"
fi
```

- Extension present and the stacks endpoint answers → **stacked flavour**
  (deltas below).
- Extension missing or the stacks endpoint returns **404** → **manual
  flavour** (the phases as written). The beta is per-repo allowlisted — a
  fresh repo of the same owner is NOT automatically enrolled (observed), and
  the feature may be withdrawn without notice. **Chuvar probed manual
  (enrolled: no) as of Jul 2026** — expect that to change; re-probe every
  batch rather than trusting this line.
- Any **other** failure (5xx, auth, network) → retry once; if it persists,
  fall back to manual and say so in the batch summary — a transient error
  must not silently lock the batch manual without a note.
- Record the flavour in each PR's Batch block. **A batch finishes in the
  flavour it started.** The only mid-batch transition is the one-way degrade
  stacked → manual via `unstack` (see Fallback), never the reverse.

## Phase 2 — Self-review

Run this before any PR opens. A finding caught here costs a
`git commit --amend`. The same finding after fan-out costs a review round,
and rounds introduce bugs.

1. For each branch, diff it: `git diff origin/main...HEAD`.
2. Ask **one pointed question** naming what the change made newly risky.
   Generic "review this" gets generic results. Usual shape: *what did this
   make asynchronous, deferred, or dependent on identity or position that
   was not before?* Here, add the AGENTS.md §6 variant: *who can now reach
   this, how do we know, and what if they lie?*
3. Delegate to a subagent — `cavecrew-reviewer` returns severity-tagged
   one-liners, which keeps the pass cheap in context. A general subagent
   works too; the lens matters more than the tool.
4. Fix findings **in the commit itself**.

Do not skip this for small changes. An eight-line change has produced three
separate defects.

## Phase 3 — Fan-out

1. Split into small, atomic, **single-commit** interstitials. Branch each off
   its parent; PR each against its parent branch. The base targets main.
2. **Open every PR ready-for-review immediately.** This trips Copilot's one
   round and starts CI. **Do not invoke Codex on interstitials** — save it for
   the aggregate pass in Phase 6.
3. Each PR body states: summary, root cause (for fixes), validation commands
   run with counts, and the Batch block below.
4. **Roster sweep (manual flavour only).** Fan-out is not complete until this
   runs. When the cap opens, one `gh pr edit` pass over every batch PR stamps
   the roster (`<slug> (#<first>–#<last>)`) and Position (`base (1/<m>)`,
   `interstitial (<n>/<m>)`, `cap (<m>/<m>)`). The stacked flavour renders
   all of this natively and has no roster sweep — see the deltas.
5. From here: **no reaction.** No replies, no fixes pushed to reviewed
   branches, no merging main in because of batch feedback.

State only what is known at write time. **Never guess ordinals, totals, or PR
numbers, and never leave `<placeholders>` live.** Writing the body before
`gh pr create` returns means the PR's own number is a guess — omit it and
stamp it in the roster sweep.

The template below is the **manual flavour's**. In the stacked flavour keep
only the policy lines — Flavour, Feedback, CI, Merge — and drop Position and
Stacked-on: the badge and stack map render them, and there is no PR number
to guess.

```markdown
## Batch
- **Batch**: <short-slug>
- **Flavour**: manual | stacked (from the Phase 1 probe; fixed for the batch)
- **Position**: base | interstitial (roster stamped when the cap opens)
- **Stacked on**: #<parent> (base: main)
- **Feedback policy**: write-only until synthesis — comments here are
  harvested and answered in the followup PR. Author-side agents: do not
  push fixes to this branch (AGENTS.md, `.claude/skills/batch-review`).
  Reviewers: review fully as normal; unanswered comments are the
  workflow, not neglect.
- **CI policy**: interstitial red is acceptable when explained by the
  stack; the followup PR is the release gate.
- **Merge policy**: operator-initiated only — no agent merges any
  batch PR without an explicit go-ahead from the human operator.
```

## Phase 4 — Bake

Normally nothing to do — the stack sits still while CI and reviews land. Two
contingencies can interrupt it; the two standing rules after them always
apply.

**Main moved for unrelated reasons.** *Manual flavour:* merge main into
affected branches — never rebase a branch carrying review context by hand.
Steps 1–4 below assume that merge. *Stacked flavour:* do **not** run them —
`gh stack rebase` then `gh stack submit` is the native operation and the
recorded exception to the never-rebase rule; the intent rules in steps 2–4
still apply to resolving its conflicts.

1. Find the branch's true payload: `git log HEAD --not origin/main --oneline`.
2. Resolve conflicts; stale hunks take main's side.
3. Audit the effective diff — what the PR still changes after the merge.
   `git diff origin/main...HEAD --stat` is a coarse scan for scope (a
   superseded PR, an unexpected file); read the **full** `git diff
   origin/main...HEAD` for anything that must be verified by content, such
   as a hunk silently reverting other work.
4. Run the focused tests. Clean merges still conflict semantically — a
   schema or primary-key change under new queries is the local shape of it.

**A showstopper lands.** For interstitials the bar is exactly one thing: **an
irreversible action on merge.** In this repo that means:

- a migration or backfill that drops or mangles persisted `facts`,
  `fact_scopes`, `grants` or `audit_log` state the moment the stack lands;
- anything that fires an unrecallable external side effect — the ntfy push
  bridge notifying real devices, an audit entry that cannot be corrected.

Fix those in place. Everything else — security findings, red CI, correctness
bugs — waits for the followup. Nothing deploys from an interstitial (there is
no CD here), and the followup merges minutes later.

If a fix does get injected into an interstitial, how it propagates depends on
the flavour:

- **Manual flavour (merge commits).** The fix usually reunifies on its own:
  it reaches main when its interstitial merges, and each child's later merge
  is a three-way against that main, so it survives to the final tree without
  touching the children. Propagate upward only when a child actually
  conflicts with the fix, needs it for its own CI to be meaningful, or the
  followup builds on it.
- **Stacked flavour (squash).** Propagate **explicitly — do not assume it
  reunifies.** Squash does not preserve ancestry: the child's merge base
  stays pre-batch, so the fix does not reach it, and the child's own squash
  can silently revert it. Amend, cascade, and then **verify the fix by
  content, not by `--stat`** — filenames and line counts cannot show that a
  conflict resolution kept the fix rather than the child's stale version.
  Grep for the fix, or run the test covering it, on each child.

**Interstitial CI red is acceptable** when the stack explains it (the fix
arrives higher up). Only the followup's CI gates the batch. Investigate a red
interstitial far enough to confirm the stack explains it — an *unexplained*
red is a real signal.

**Mid-batch events are ledger entries, not work orders.** Triage any webhook
or CI status against the showstopper bar, record it for synthesis, stand
down. Claude Code's per-PR auto-fix toggle cannot see the stack; enable it
only on the followup, if at all.

## Driving phase transitions

Wake on conditions, with a bounded fallback — both halves are deliberate.
Arm a watch for the completion signal and **act the moment it fires**; carry
a fallback timer so a bot no-show cannot stall an unattended batch. When the
fallback fires instead, **proceed with what has arrived** and record the
no-show in the ledger — do not re-arm and keep polling, and do not stop to
ask.

**Fan-out → synthesis.** Wake the moment every interstitial has a concluded
CI run **and** a Copilot review; fall back at ~30 minutes for the whole
stack's bake. (A single re-solicited review — either bot — gets ~10 minutes
from the request before its silence counts as a no-show; Phase 6 carries the
same numbers.)

- **Do not wait on Codex.** With auto-review off it never posts to an
  interstitial; including it burns the fallback every batch.
- **CI always concludes here**, because `ci.yml` filters per job rather than
  per workflow, so the run always starts. "Every interstitial has a
  concluded CI run" is always reachable and needs no special case — but
  green with both halves skipped means nothing ran, and nothing says so.

**Followup reactivity.** Watch the followup by subscription + CI from the
orchestrating session, which holds the batch ledger. Not a toggle-spawned
fresh session.

**Followup green → merge.** When the followup's CI is green **and** every
thread is answered — fixed, ticketed, or marked not-relevant; a thread closed
with "ticketed as <link>" counts — wake once to *report* the stack is ready
and ask for the go-ahead. Readiness is never itself the go-ahead.

## Phase 5 — Synthesis

Deliverable: a per-PR verdict plus batch-level findings.

Harvest every comment across the stack:

```bash
gh pr view N --json comments                      # issue comments
gh api repos/{owner}/{repo}/pulls/N/reviews       # review bodies
gh api repos/{owner}/{repo}/pulls/N/comments      # inline — the substance
```

**Filter agent bookkeeping out of the review record.** Agent-posted thread
replies use the operator's `gh` credentials, so they appear as human reviews
at the current SHA. Separate genuine reviews from replies by `in_reply_to_id`,
not by author.

Add your own aggregate review for what per-PR reviewers structurally miss:
cross-PR interactions, sibling inconsistency (same problem solved two ways),
gaps *adjacent* to a PR's purpose — a boundary PR that hardens one principal
chain but not its twin. Apply AGENTS.md §6's trust-boundary questions across
the whole surface, not per file.

Triage on merit — bots only had per-PR context:

- Citing a convention (AGENTS.md §3.1, §3.2, §6): verify the citation, then
  act.
- Claiming runtime behaviour: verify against the code. Fix only what you can
  trace or reproduce; say so when a claimed bug can't be.
- Re-litigating deliberate design, or already answered by a later
  interstitial: mark not-relevant with a one-line reason.

## Phase 6 — The followup PR

One PR, stacked on the cap, carrying all reactive work. It contains:

- Every actioned item grouped by source PR, with reviewer and severity.
- Doc updates for anything the batch mitigated or changed.
- A section for comments **assessed and not actioned**, with reasons. This
  keeps the write-only bargain honest.
- One full validation pass over everything touched — backend suite with
  `-p 1` and `DATABASE_URL`, `go vet`, sqlc drift check, frontend lint,
  build and tests. Not per-comment runs.
- Batch block: `Position: followup — live feedback surface and release gate;
  must be robust and green before the stack merges; squash-and-merge.`

Then resolve every interstitial thread: `fixed in the followup (#<n>)` or
`not relevant: <one line>`. This is the only time the batch touches its own
review threads. In the same pass, append `- **Followup**: #<n>` to each Batch
block — in **both** flavours. It is a policy line, not a position line: the
stack map renders parentage but has no concept of which PR carries the
reactive work, so it stays even in the trimmed stacked block.

The followup is the one place to watch the live dripfeed. Its bar is broader
than an interstitial's, because it is the release gate: fix anything that
would ship broken — correctness bugs, security findings, red CI — in place.
Everything below that seeds the next batch.

### Opening it: draft-first aggregate review

The followup is the one moment the whole batch exists as a single reviewable
diff. Spend the Codex budget here.

1. **Open as a draft, base = `main`.** The diff becomes `main...followup` —
   the entire stack plus reactive work. Draft is the safety wrapper: a
   followup targeting `main`, if merged, squash-merges the whole stack into
   one commit. A draft cannot be merged.
2. **`@codex review`.** Codex answers on drafts; Copilot won't fire until
   step 5. Comments only, no commits.
3. **Harvest the findings before touching the base.** Retargeting narrows the
   diff and can orphan threads anchored to lines that leave it.
4. **Retarget to the cap:**
   ```bash
   gh api -X PATCH repos/{owner}/{repo}/pulls/N -f base=<cap-branch>
   ```
5. **Stacked flavour only: link the followup into the stack object** —
   between the retarget and marking ready. Skip this and the followup stays
   a loose PR outside the stack, which the Phase 7 pre-flight is supposed to
   catch. The mechanism is **UNVERIFIED**; see the deltas for the candidates
   and the degrade path if it misbehaves.
6. **Mark ready.** The draft→ready edge triggers Copilot on the now-narrow
   diff.

### Re-soliciting review per round

**Nothing reviews on push.** Copilot fires only on the ready edge; Codex only
on invocation. Neither *auto*-reviews a draft — but Codex still answers an
explicit `@codex review` on one, which is what step 2 of the draft-first
flow above relies on. Every round must ask again.

```bash
gh api repos/{owner}/{repo}/pulls/N/requested_reviewers -X POST \
  -f 'reviewers[]=copilot-pull-request-reviewer[bot]'
```

- `@codex review` only when a round warrants the quota: correctness fixes in
  cross-cutting code, not comment tweaks.
- **Either re-solicitation gets ~10 minutes** — from the Copilot re-request,
  or from the Codex invocation or its 👀 reaction. Silence past that is a
  no-show: record it and proceed.
- Comments only, no commits. Every time.
- Keep a `## Review focus` section current per round:

```markdown
## Review focus
- **Highest risk**: <what this round made newly risky, in one line>
- **Verify, don't assume**: <the specific path a reviewer should trace>
- **Out of scope**: <decided in #N / ticketed as <link> — do not re-raise>
- **Comments only, no commits** — this branch is write-only under the
  batch workflow.
```

### Never trust an aggregate review signal

| Signal | Why it lies | Check |
|---|---|---|
| "Zero unresolved threads" | Identical whether feedback was answered or never solicited | Verify `commit_id` — an earlier SHA has not seen current work |
| "Generated no new comments" | Real bugs sit in the suppressed-confidence block below it | Open the `<details>` block |
| "Reviewed N out of M changed files" | A partial pass reading as a complete one | Read the count; close the gap yourself in synthesis |
| A new test passing first run | It may pass against unfixed code — a harness not matching production | Show it failing first. If it won't fail, the harness is wrong or the bug isn't there (AGENTS.md §6) |
| A green CI run | Both halves may have skipped — green means "no failures", not "tested" | Check which jobs actually ran, not just the colour |

### Cap the reactive rounds at three

Reactive fixes introduce bugs often enough that more rounds is not better.
**When a round's findings are all in code the previous round wrote, that is
the cap arriving** — regardless of how few files are in play.

At the cap, or once findings stop being correctness regressions:

- Fix only genuine defects in shipped behaviour.
- Everything else becomes a **Notion task** with the finding, reasoning, and
  acceptance criteria — metadata set, per Repo specifics.
- If one small change draws three or more findings, **revert and ticket it**.
  It needs design time, not another patch.

## Phase 7 — Merge the stack

**Gate: never start without the operator explicitly saying to merge now.** A
synthesis pass, a green followup, and an auto-mode session default are not
that signal. This holds even when the rest of the workflow runs autonomously.
If the stack is ready, say so and stop.

**Pre-flight: confirm the followup's base is the cap, not `main`.**

```bash
gh pr view <followup> --json baseRefName
```

A followup still targeting `main` squash-merges the entire stack into one
commit. Fix by retargeting, not by trusting memory.

Then, **manual flavour**, merge interstitials bottom-up, one at a time.
(Steps 1–4 do not exist in the stacked flavour — the platform sequences the
train and auto-deletes branches; there the agent's Phase 7 is confirm,
report, stop. See the deltas.)

1. `gh pr merge <n> --merge` — a **plain merge commit**, and **no
   `--delete-branch`.** Each merge commit wraps exactly one reviewed commit,
   and preserving ancestry is what keeps children mergeable.
2. Poll `gh pr view <n> --json state,mergedAt` until `MERGED`. With a merge
   queue, `gh pr merge` can return after merely enqueueing, and this workflow
   tolerates red CI — "the command returned" is not "it merged".
3. Confirm the next PR's base is now `main`; retarget explicitly if not:
   `gh api -X PATCH repos/{owner}/{repo}/pulls/<next> -f base=main`.
4. Only now delete the merged branch. ("Remote ref does not exist" means the
   repo auto-deleted it — benign, and confirms the retarget landed.)

Never let `--delete-branch` race GitHub's auto-retarget: deleting a base
branch out from under a not-yet-retargeted child closes the child. Observed
here on #5→#6 — `gh pr merge 5 --delete-branch` closed #6 because
`pr/05-store` vanished before GitHub retargeted it.

**If a child does get closed:** push the branch back from its last known SHA,
reopen (`gh api -X PATCH repos/{owner}/{repo}/pulls/<n> -f state=open`),
retarget to main, then delete. No work is lost — commits stay reachable from
the SHA.

Merge rapidly and consecutively. The followup merges last, squash-and-merge.
Recommend an order for independent PRs; the choice is the operator's.

## Phase 8 — Cut the release tag

A merge is not a release.

Once the followup is merged and main is green on the merged tip:

```bash
bin/release-tag
```

It tags `origin/main` as `v<UTC yyyymmddHHMM>` and pushes it.

- The script refuses a main that isn't green, and re-checks that main hasn't
  moved between the check and the push.
- `--dry-run` prints the tag and target without creating anything.
- One tag per train, not per PR.
- Applies outside this workflow too, after any solo impactful commit on main.
- **There is no image build yet** (AGENTS.md §5), so the tag currently marks
  a release point and produces no artefact. When a build lands it should
  trigger from `v*`, and every tagged train is already a candidate. Don't
  read "no image appeared" as a failure before checking whether a build
  exists at all.

## Stacked flavour — deltas from the phases above

Everything not listed here is unchanged. These rules were tuned against
observed behaviour in a sibling repo; treat them as recorded observation, not
as guarantees the beta will keep.

**Fan-out (Phase 3).**
- Branch via the tooling: `gh stack init <b1>`, commit, `gh stack add <b2>`,
  commit, … Use **virgin branch names**: `init`/`add` silently adopt an
  existing local branch of the same name, stale base and all (observed).
- **Worktree hazard**: every trunk reference uses the *local* `main` ref. A
  stale primary checkout makes `init` base branches on old history and makes
  `rebase` report "✓ rebased onto main" without doing it (observed, twice).
  Keep the primary checkout's `main` fast-forwarded, and verify every
  claimed trunk rebase with `git merge-base --is-ancestor origin/main
  <branch>` — trust the ancestry check, not the ✓.
- `gh stack submit --auto` creates the PRs **as drafts** — flip each
  ready immediately (`gh pr ready <n>`) to start Copilot's round, same as
  the manual flavour's open-ready rule.
- **After any history rewrite, push with `gh stack submit`** — `gh stack
  sync` reports "✓ synced" without pushing rewritten branches (observed).
- The Batch block keeps only its **policy lines** (feedback, CI, merge
  policy + flavour). Position, parent, and roster are rendered natively by
  the stack badge (`n/m`) and stack map — the roster sweep does not exist in
  this flavour, and there is no PR-number guessing to avoid.

**Bake (Phase 4).**
- Main moved: `gh stack rebase` then `gh stack submit`. Rebase is the
  native operation here and the "never rebase a reviewed branch" rule is
  **suspended for tool-managed restacks**: review threads were observed
  surviving local cascade rebases, hunk-rewriting amends, trunk rebases and
  the stack merge itself — GitHub re-anchors threads to the new SHAs.
  Spot-check `position != null` on planted threads after each restack
  anyway; the observation is empirical, not contractual.
- The "out-of-date with base" banner is advisory — the stack still merges
  onto the true current main (observed).
- **A showstopper fix propagates by amend, not by merge commits**: amend the
  interstitial's commit, `gh stack rebase` (the cascade replays every
  child), `gh stack submit`, then verify the fix **by content** on each
  child — the manual flavour's merge-the-parent-into-children mechanism
  fights tool-managed linear branches.
- Rebase conflicts during a restack are **normal work, not misbehaviour**:
  resolve with the same intent rules as the manual flavour (stale hunks take
  main's side; the child's own changes win over a parent's superseded
  payload), then continue. "A stack operation misbehaves" in the Fallback
  means tool errors — not a conflict prompt.

**Followup (Phase 6).** Open it as a plain draft PR targeting `main` — *not* yet in
the stack object — and run the aggregate `@codex review` exactly as in
Phase 6. After harvesting: retarget its base to the cap, link it into the
stack object, then mark ready (the ready edge buys Copilot's round on the
narrowed diff, as in the manual flow). **The linking step is UNVERIFIED** —
`gh stack submit` from the branch or the stack map's "Add to stack" are the
candidate mechanisms, neither observed yet. If linking fails or misbehaves,
do not fight it: leave the followup as an ordinary PR on the cap and finish
it with the manual Phase 7 choreography after the stack merges — the
followup degrades independently of the interstitials.

**Merge (Phase 7).**
- The operator gate is **platform-enforced**: `gh pr merge` refuses stacked
  PRs, the CLI has no merge command, and the merge control is the web UI's
  stack button only. The agent's Phase 7 is therefore exactly: confirm every
  PR Ready and every thread answered, report, stop. The click is the
  operator's by construction.
- **Use "Squash and merge stack".** Observed result: one squash commit per
  PR, bottom-up, `title (#N)` messages, per-PR merge attribution — the same
  one-commit-per-PR history the manual flavour's merge train produces. The
  stack *button* cannot collapse the stack — but the followup spends its
  aggregate-review window as an ordinary draft targeting `main` (see above),
  where the manual collapse risk exists unchanged. **The pre-flight survives
  in stacked form**: before reporting ready for the click, confirm the
  followup's base is the cap AND it appears in the stack map — verify the
  link happened, don't assume it.
- Do **not** use "Create a merge commit stack" expecting per-PR merge
  boundaries: observed, it produces the stack's raw commits under a single
  wrapper merge of the *top* PR, with every PR sharing that one merge
  commit.
- The per-PR retarget/poll/delete choreography does not exist in this
  flavour — the platform sequences the train and auto-deletes branches.

**Fallback.** Two triggers, one direction:
- The Phase 1 probe fails → manual flavour, no stack tooling at all.
- Anything breaks mid-batch (extension vanished, stack API errors, a stack
  operation misbehaves) → **degrade once, permanently, for that batch**:
  `gh stack unstack` (or the stack map's unstack control) dissolves the
  stack object — observed non-destructive: PRs stay open as ordinary PRs
  with correct bases, branches intact — then finish under the manual
  phases, including the full Phase 7 choreography. `gh pr merge` works
  again once the stack object is gone — which also means the platform's
  merge block is gone: **the operator gate reverts to policy**, and it
  binds exactly as it always did.

## Rules of thumb

- Probe the flavour first (Phase 1); record it; finish the batch in it.
  Stacked degrades to manual via unstack — never the reverse, never midway.
- Self-review before any PR opens. One pointed question per branch.
- Feedback is write-only until synthesis. No replies, no mid-stack pushes.
- Interstitials: Copilot's one round, one commit each. Followup: N commits,
  squash-merged, the only live-feedback surface and the release gate.
- Codex is invocation-only and aggregate-first. 2–3 invocations per batch.
  ("Manual" always names the workflow flavour, never a bot's trigger mode.)
- Manual flavour merge-commits the interstitials and squashes the followup;
  the stacked flavour squashes the stack. One commit per PR on main either
  way.
- Merge main into a batch branch only when the world moved outside the batch:
  payload first, effective-diff audit after — the full diff, not `--stat`,
  for anything verified by content.
- Never rebase a reviewed branch by hand (manual flavour). Tool-managed
  restacks in the stacked flavour are the exception — verified, threads
  re-anchor.
- Merge bottom-up. Retarget each child before deleting its parent's branch
  (manual flavour; the platform sequences the stacked train).
- Phase 7 needs an explicit, per-batch go-ahead. Never self-initiate.
- Only the followup's CI gates the batch. Unexplained red is a real signal —
  and a *skipped* job is not a passing one.
- Interstitial showstopper bar: irreversible action on merge — nothing else.
  The followup's is broader: anything that would ship broken, since it gates
  the release.
- Cap reactive rounds at three, or the moment a round's findings are all in
  the previous round's code. Past that, fix real defects, ticket the rest.
- Never trust an aggregate review signal.
- A merge is not a release.
- Write every deferral down as a Notion task in the Memory Vault Tasks
  Tracker, metadata set — not a GitHub issue, not a PR-body table.

## Evidence

**A prior batch in another repo (six interstitials + followup), seven
reactive rounds.**
Findings per round: 6 → 2 → 1 → 3 → 2 → 5 — not convergence. Fan-out worked:
26 real findings, several data-loss bugs that would have reached users. The
tail did not: four of five later rounds found defects created by a previous
round's fix. Three tests written to prove fixes passed against unfixed code.
One eight-line change drew three defects and was eventually reverted.

**The bot split is measured, not assumed.** Over that batch Copilot found
every instance of a mechanical bug class (6/6) and both bad-test cases; every
Codex finding that mattered was cross-file. That is why Copilot runs on every
PR unrationed and Codex is spent on the aggregate diff — not a preference
about tone or quality.

**A sibling repo's four-file change that still hit the cap.** Every round's
fix produced the next round's finding. Copilot found both mechanical defects,
each in code the previous round had just touched; Codex's single aggregate
pass found three ordering bugs on the seam between the PRs. Neither found the
other's. The sharpest finding was a fix worse than its bug: an error path that
deleted a local tag after a failed push, so a dropped connection would cut a
second release for the same train.

**The stacking probe (sibling repo).** A planted review thread survived a
local cascade rebase, a hunk-rewriting amend, a trunk rebase and a full stack
merge without ever orphaning. Stack-squash produced history matching the
manual train; stack-merge-commit collapsed per-PR merge boundaries into one
wrapper. `gh pr merge` is platform-blocked on stacked PRs. `sync` false-greened
on rewritten history; `rebase` and `init` silently used a stale worktree
`main`; `unstack` degraded cleanly to ordinary PRs. A fresh repo was not
enrolled in the beta even when public. Every stacked-flavour rule above traces
to one of these observations — with one exception, the followup
link-into-stack step, which is marked UNVERIFIED where it is stated.

**Why the round cap is hard, not advisory.** Review is worth most before work
is published and progressively less after, because every later finding is
fixed under pressure against a stack that resists change. A reactive round
also drains every budget at once — bot credits, model tokens, CI minutes. One
such batch consumed half a month's paid Actions minutes across three days.
