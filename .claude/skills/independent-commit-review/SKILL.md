---
name: independent-commit-review
description: Run an adversarial, fresh-eyes review over a range of local commits before they're pushed or handed to someone else — one independent subagent per commit (or per tightly-coupled group), fold verified fixes back into history via cherry-pick, with a safety snapshot throughout. Use before pushing a batch of commits meant to become standalone PRs, or whenever asked for a "critical review" of work already committed.
---

# Independent commit review

This is the process from the Memory Vault v0 build's post-hoc review (Jul 2026):
12 commits were built fast, then reviewed commit-by-commit by subagents that had
never seen the code, and 9 of 12 needed real fixes — including a subject-spoofing
auth bypass and a SQL wildcard-escaping bug that let ungranted facts leak. Doing
this *after* the fact meant rewriting published-looking history to fold the fixes
back in cleanly. See AGENTS.md's "Review discipline" section (§6) for the cheaper
alternative: do this per-commit, during the build, not as a single expensive pass
at the end. Use this skill for the version of the job that's already needed —
either because review didn't happen incrementally, or because a self-contained
batch of work explicitly warrants a second set of eyes before anyone else sees it.

## Why subagents, not self-review

Re-reading your own commits is anchored: you already decided the tricky bits were
fine when you wrote them. A subagent that starts cold, with no memory of writing
the code, catches things a self-review reliably misses — this is the whole reason
the pass in this session found a real auth bypass and a real SQL bug that survived
the original build, tests, and a first-pass self-review of the small commits.

## Step 1 — Safety snapshot, before touching anything

```
git branch snapshot/pre-review-<date> <branch-being-reviewed>
```

Do this even though you're not planning to force-push anything yet. History
rewriting is coming; a snapshot branch means "something went wrong" is a
`git branch -f` away from recoverable, not a `git reflog` archaeology project.

## Step 2 — Identify review units

One unit per commit that's meant to become its own PR. If several tiny commits
are really one logical change (e.g. a one-line follow-up patch to a package two
commits later), review them together — say so explicitly in the agent prompt so
it doesn't waste time re-deriving that they're related.

Skip units with no real logic (pure docs/config) unless something about them is
genuinely risky (e.g. a docker-compose file with a port binding or a checked-in
credential — these are exactly the kind of "boring" commit that hides a real
finding, as `docker-compose.yml`'s missing `127.0.0.1` bind was in this session).

## Step 3 — Dispatch one independent agent per unit, in parallel

Use the `Agent` tool, `subagent_type: general-purpose`, all launched in one
message so they run in parallel and in the background. Do **not** review the
commits yourself first and then ask the agents to confirm — that defeats the
"fresh eyes" property this whole skill exists for.

Each prompt needs:

1. **The exact commit SHA(s)** and the literal `git show <sha>` command to run —
   don't paste the diff yourself; let the agent read the real repo state,
   including files the diff doesn't show but that provide context.
2. **Project context**: what this codebase is, and an explicit pointer to read
   AGENTS.md (or the project's equivalent) first, since the review should be
   judged against this project's own stated invariants, not generic best
   practice.
3. **A skeptical framing**: "act as a strict reviewer seeing a stranger's PR for
   the first time, no reason to be charitable." Vague "please review this" prompts
   produce polite, shallow output — see the fable/writing-prompt guidance
   elsewhere in this org: specificity produces rigor.
4. **What to hunt for, concretely**, tailored to what that commit actually does —
   not a generic checklist. Good targeting questions from this session:
   - For anything on a security/access-control boundary: "trace the actual code
     path — can a caller manipulate X to see/do something they shouldn't? Don't
     guess, verify by reading the code."
   - For SQL: "is every value parameterized? Could this string ever contain a
     character with special meaning to the query operator being used (LIKE
     wildcards, regex metacharacters)?"
   - For concurrency: "what happens if this function runs twice at once against
     the same row — trace the actual lock/transaction behavior, don't assume."
   - For error handling: "does any error message reach an external caller
     verbatim? Could it leak internals?"
   - For anything with a "known gap" comment already in the code: "is the stated
     scope of that gap accurate, or does it actually cover less than the comment
     claims?"
5. **Output format**: findings ranked by severity (blocker/major/minor/nit), each
   with file:line, the concrete failure scenario (not just "this could be
   risky"), and a suggested fix. A clear verdict at the end (approve / approve
   with nits / request changes). Cap the length (400–600 words) so triage is fast
   — a review that hedges into a wall of text is as useless as one that's too
   thin.

## Step 4 — Triage findings as they land

Background agents report back via notifications, not all at once — read each as
it arrives rather than waiting idle for all of them (see the parent skill/session
guidance on background agents: don't poll, don't fabricate results, keep working).
As each finding lands, form a real opinion on whether it's:

- **Must-fix now** — anything that's concretely reachable, not hypothetical, and
  touches correctness, security, or the project's own stated invariants.
- **Worth strengthening a comment/doc for, not code** — e.g. a "known gap" that's
  accurately scoped and already an explicit, deliberate decision; make the
  documented severity match reality without necessarily building a fix (auth on
  the REST API in this session was this case — real gap, correctly already
  flagged, fixing it meant a genuine unmade product decision, not a bug).
- **Follow-up, not blocking** — real but low-severity/low-likelihood; note it and
  move on rather than let scope creep swallow the review.

Don't accept a finding uncritically either — subagents can be wrong or overstate
severity. Spend a moment verifying the concrete failure scenario actually holds
before committing to a fix.

## Step 5 — Fix with revert-and-confirm verification

For anything you fix, especially security/correctness bugs: write (or extend) a
regression test, confirm it passes with the fix in, then **temporarily revert
just the fix** (not the test) and confirm the test now fails for the right
reason, then restore the fix. This is the single highest-value habit from this
session — it's the difference between "I wrote a test that happens to pass" and
"I proved this test catches the actual bug." Two real bugs in this session
(the LIKE-escaping issue, the CommitDiff race) were confirmed exploitable this
way, and one test bug in the reviewer's own fix attempt (a native `<input
type="number">` silently blocking submission before custom JS validation could
run) was *caught* by doing this — the revert-and-confirm step is also how you
find out your fix doesn't actually do what you think.

## Step 6 — Rebuild history with the fixes folded in

Don't just stack new "fix review comments" commits on top — fold each fix into
the commit it belongs to, so each PR-to-be looks like it was written correctly
the first time. The reliable, scriptable way to do this without fighting
`git rebase -i`'s need for an interactive editor:

```
git checkout -b <range>-rebuilt <first-commit-in-range>~1   # or the true root
git cherry-pick <commit-1>
# make fixes, test, then:
git add -A && git commit --amend --no-edit   # or -m "..." to rewrite the message too
git cherry-pick <commit-2>
# ...repeat for every commit in the range...
```

Expect conflicts on any file touched by more than one commit in the range —
`go.mod`/`go.sum`/lockfiles are the most common culprits, since amending an
earlier commit to add or remove a dependency shifts what every later commit's
diff expects to find. Resolve by taking the amended (earlier, already-fixed)
version's structure and re-merging in whatever the later commit's cherry-pick
was trying to add — read both sides of the conflict marker, don't blindly pick
one. Rebuild, `go build`/`go vet`/test after *every* cherry-pick, not just at the
end — a conflict resolved wrong fails fast this way instead of surfacing three
commits later as a mystery.

When the fix touches shared test setup and a later commit's test file also
touches it, expect a conflict there too (this session hit one merging two
commits' additions to the same `_test.go` file) — resolve by keeping both
additions, not by picking a side.

Rewrite each commit message as if it's the final PR description: what changed,
why, and — critically — document what review found and how you verified the fix,
in the commit itself. Future readers (including a future you) benefit from that
history being honest about what almost shipped broken and why it didn't.

## Step 7 — Final verification and cutover

Run the full test suite (and build/vet/lint) against the rebuilt branch from a
clean starting state — for this project, that means a freshly recreated
Postgres (`docker compose down -v && docker compose up -d`) so migrations and
integration tests run against exactly what a new contributor would see, not
whatever state was left over from development.

Then move the real branch:

```
git checkout <original-branch>
git reset --hard <range>-rebuilt
git branch -d <range>-rebuilt
```

`snapshot/pre-review-<date>` from Step 1 stays untouched — leave it. It costs
nothing to keep and it's the only way back if something surfaces later that the
review missed.

## Environment notes that cost time in this session

If you hit these while running through the steps above, they're not a sign
something's newly broken — see AGENTS.md's "Known environment gotchas" (§4.5)
for the full list (mise's shell hook not being active in tool-invoked shells,
docker needing `sudo -n`, the sibling `spritz` project's port claims, zsh
reserving `status` as a variable name, and why the full test suite needs
`go test -p 1`).
