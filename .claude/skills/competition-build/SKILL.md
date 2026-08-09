---
name: competition-build
description: Build a security-critical feature by running 2–3 independent implementations of the same brief in parallel, judging each adversarially, and shipping only the survivor — escalating to a more capable model only when every attempt has blocking holes. Use when the user asks to "orchestrate" rather than implement, hands off a body of security-sensitive work to run unattended, asks for competing/independent attempts at a problem, or when a feature sits on a trust boundary where a single implementer's blind spot would ship a bypass. Feeds the surviving branches into `.claude/skills/batch-review`; verify the combination with `.claude/skills/stack-integration-check` before any of it is pushed.
---

# Competition build

For work where a bug is a security calamity, redundancy beats depth. Three
implementers who never saw each other's code fail in different places; one
implementer plus one reviewer fail in the same place.

**The bargain: nothing ships until it has survived a judge that was trying to
kill it.** Attempts are cheap and disposable. Only the survivor becomes a PR.

**Opt-in.** The default here is one implementation, reviewed per-commit
(AGENTS.md §"Review discipline"). Reach for this skill when the feature sits on
a trust boundary — auth, key custody, scope/permission matching, anything where
"who is calling and what if they lie?" has a non-obvious answer — or when a
large body of such work must run unattended.

## Terminology

| Term | Meaning |
|---|---|
| **Brief** | The single prompt every attempt receives. Identical across attempts. |
| **Attempt** | One independent implementation on its own branch. Disposable. |
| **Judge** | An adversarial reviewer of one attempt, trying to find a bypass. |
| **Blocking hole** | A finding that is reachable, not hypothetical, and breaks correctness, security, or a stated invariant. |
| **Survivor** | The single attempt that ships. Exactly one per feature, or none. |
| **Escalation** | One run at the expensive model tier, given all attempts + all findings, when no attempt is clean. |
| **Hold-out** | A feature with no clean survivor even after escalation. Ships nothing; goes to the operator with attempts and findings. |

## Hard constraints

These are not negotiable and every subagent prompt must restate them:

- **No subagent pushes. Ever.** Attempts commit to local branches only.
- **No subagent touches `main`.**
- **The shared dev Postgres on port 54322 is off limits.** Agents spin up their
  own disposable container and tear it down. Never set `DATABASE_URL` to 54322.
- **Only the survivor is pushed.** Losing attempts stay local; do not open a PR
  "for comparison".
- **Merging needs the operator's explicit go-ahead**, per batch, even in auto
  mode. Opening a PR is not merging.
- Backend suite needs `mise exec --` and `go test -p 1`. `go test -race` does
  not work on this host (TSan VMA range) — do not let an agent burn a cycle on it.

## Phase 1 — Spike, if the design has an unknown

Only when a design decision turns on how something actually behaves. Skip it
when the mechanism is understood.

**Ask for a running prototype, not a memo.** The socket-authorization spike
earned its keep because it *built* an `execve`-on-the-same-PID shapeshifter and
demonstrated that a `/proc/<pid>/exe` check after `SO_PEERCRED` reads
attacker-mutable state. A spike that reasons about that lands as an opinion; a
spike that exploits it changes the design.

Spike output is evidence and it evaporates when the session ends. **Land the
findings in `docs/` in the same batch** — `docs/broker-spikes.md` exists because
the applied conclusions were in code comments but the evidence was only in
`/tmp`. Findings that record a *negative* result matter most: "this host happens
to block the cheap PID-reuse race, but that is a local kernel-config accident and
must not be designed against" is unrecoverable once lost.

## Phase 2 — Write the brief

One brief, issued verbatim to every attempt. It needs:

1. **The invariant in the imperative, not the feature in the abstract.** "An
   untargeted grant must not cover a targeted request" beats "implement scope
   targets".
2. **A pointer to CLAUDE.md and AGENTS.md**, and the instruction to judge the
   design against *this project's* stated invariants rather than generic best
   practice.
3. **The named adversary.** Who is attacking this, with what access?
4. **Known bug classes from earlier attempts at adjacent work**, spelled out.
   This is the cheapest quality lever in the whole skill — see Phase 4.
5. **The hard constraints above**, restated.
6. **What "done" means**: which tests, run how, and the revert-and-confirm
   requirement (write the regression test, see it pass, revert *only* the fix,
   see it fail for the right reason, restore). A test never seen to fail has
   proven nothing.

**Brief the merge, not just the code.** When an attempt must build on another
branch, name the paths explicitly and require it to `git diff` against the branch
below and justify every deletion. The worst defect of the first run was an
attempt that took one package wholesale as a file-level copy and silently dropped
a security control the branch below it had introduced. The merged result was
correct; the individual PR was not — which is exactly the shape a reviewer
catches and loses trust over.

## Phase 3 — Run 2–3 independent attempts

Parallel, isolated, same brief. Use `isolation: 'worktree'` when attempts touch
the same paths — they will.

Independence is the whole product. Do not let attempt 2 see attempt 1's code, do
not summarise attempt 1's approach into the brief, and do not review attempt 1
yourself first and hand the judges your opinion.

## Phase 4 — Judge each attempt adversarially

One judge per attempt minimum; more lenses for the highest-risk features. Give
each judge a **distinct lens** (correctness, bypass-hunting, does-it-actually-run)
rather than N identical reviewers — diversity catches failure modes redundancy
cannot.

Judge prompts need:

- **The exact artifact.** State whether the target is *the branch as it would be
  reviewed as a PR* or *the merged result on top of its base*, and why. A judge
  aimed at a feature branch once reported CRITICALs that were already fixed on the
  merged stack — not wrong, just pointed at the wrong thing.
- **The known bug class, named.** Three independent WebAuthn implementations
  shipped the *same* critical bug: an "ever-enrolled" bootstrap gate that counted
  TOTP rows but not passkeys, leaving self-mint open in a passkey-only deployment.
  Independent attempts converge on the same blind spot. Once one attempt's bug
  class is known, put it in every later judge's prompt by name and they hunt for it.
- **Scoring that cannot drift.** Ask for an integer 0–10 and say "0-10 ONLY, not
  a percentage" in the schema description — judges asked for 0–10 have returned
  93 and 95. Then **do not threshold on the score**: threshold on blocking-hole
  count. The count is the decision; the score is colour.
- **A length cap, in both the prompt and the schema description**: "UNDER 1500
  chars, do not paste diffs or logs". An entire workflow once died on
  `StructuredOutput retry cap (5) exceeded` because a judge kept emitting an
  oversized report — while the work itself was already committed and correct.

## Phase 5 — Pick the survivor, or escalate

- **Exactly one attempt clean** ⇒ it is the survivor.
- **More than one clean** ⇒ take the one whose *tests* are strongest, not the one
  with the most code.
- **Every attempt has blocking holes** ⇒ **escalate once**: synthesise every
  finding, hand the expensive tier all attempts plus all findings, and have it
  build the survivor. Do not pre-assign the expensive tier to a whole phase —
  let the judges decide when it is needed. On the first run this fired exactly
  once, for the one feature where all three attempts had holes, and produced a
  clean result first try.
- **A survivor with a narrow, non-bypass gap** (a missing UI path, an incomplete
  error case) ⇒ one targeted fix pass, then re-judge. Do not re-run the whole
  competition for a completeness gap.
- **No clean survivor after escalation** ⇒ **hold out**. Ship nothing for that
  feature and bring the attempts and findings to the operator. Surfacing beats
  discarding; the decision to ship a known-holey thing is not an agent's to make.

## Phase 6 — Verify the combination, early

**Run `.claude/skills/stack-integration-check` as soon as candidate branches
exist**, not as a last gate before push. Per-branch review structurally cannot
catch two branches that implemented the same shared abstraction in opposite
directions, and green suites are what hide it. Running it early on the first run
is what made the semantic fork cheap to fix instead of a post-push archaeology
project.

## Phase 7 — Hand off to batch-review

Survivors become the interstitials of a normal stack. From here,
`.claude/skills/batch-review` owns the process: feedback write-only, one
synthesis pass, one followup PR, merge bottom-up on the operator's explicit
signal. Competition does not usurp that flow — it decides *what* enters it.

## Never trust a subagent's report

The report and the artifact are different objects, and the artifact is the one
that ships. Before relaying any agent claim that would change what ships, read
the diff, grep the branch, run the command — then say which of the two you are
relaying.

| Signal | Why it lies | Check |
|---|---|---|
| A judge's CRITICAL | May be true of a different artifact than the one shipping | `git diff` the branch against the one it stacks on |
| `summary: "test"` or other garbage structured output | The agent can do correct work and fail only at reporting | `git branch` / `git log` on the branch it claimed |
| A crashed workflow | Same — commits survive the crash that killed the report | `git log` before assuming work was lost |
| Two agents contradicting each other | Both are often right about different artifacts | Diff the two artifacts against each other |
| A green suite on both of two branches | Each may test only cases that pass under either semantics | Compare the shared code path directly, not the suites |

## Model tiering

Cheap-first, escalate on evidence. Attempts and judges run at the standard
implementation tier; the expensive tier is spent only where Phase 5 says every
attempt failed. Bulk mechanical work goes to subagents or plain scripts, never to
a capable main thread.

If the operator is fighting the model selector, discuss tiers by role ("the
escalation tier", "the main thread") rather than by model name — naming models in
conversation can trip a classifier that flips the session model.

## Evidence — what the first run actually proved

Chuvar capability broker, overnight 2026-08-09. Two research spikes, three simple
builds, two three-way competitions with adversarial judging, one escalation,
fresh-eyes review and fix passes, stack-integration verification. Six PRs, none
merged without the operator.

What redundancy caught that depth would not have:

- All three WebAuthn attempts shipped the identical bootstrap-gate bug. A single
  implementer ships it; a single reviewer probably misses it.
- Two branches wrote opposite `scope.Covers` semantics for the same case, both
  suites green, because each only tested cases that pass identically either way.
- One branch deleted a security control introduced by the branch below it in the
  stack, while its own tests stayed green.

What cost time and is now prevented above: judges drifting off the scoring scale,
a workflow dying on an oversized structured report, a judge aimed at the wrong
artifact, and spike evidence that lived only in `/tmp`.
