---
name: stack-integration-check
description: Verify that a set of candidate branches actually combines correctly before any of them is pushed or opened as a PR — catching cross-branch semantic forks (two branches implementing the same shared abstraction in opposite directions, both suites green), controls silently deleted by a file-level "merge", and content-without-ancestry branches that make two PRs appear to add the same code. Use whenever more than one branch is in flight against the same package, before opening a stack of PRs, after any agent-performed merge or rebase, or when two reports about the same code contradict each other.
---

# Stack integration check

Per-branch review is structurally blind to what happens *between* branches. Each
branch can be individually correct, individually tested, individually green — and
the combination still wrong. This is the check that runs on the combination.

**Run it as soon as candidate branches exist**, not as a last gate before push. A
semantic fork found while the branches are still local is a one-commit fix; found
after the PRs are open it is an archaeology project across published history.

## What this catches

| Defect | Why per-branch review misses it | Real instance |
|---|---|---|
| **Semantic fork** | Two branches implement the same shared function in opposite directions. Both suites pass because each only tests cases that behave identically under either rule. | Two branches wrote opposite `scope.Covers` semantics for untargeted-grant-vs-targeted-request — fail-closed on one, fail-open on the other. |
| **Silently deleted control** | An agent "merges" by copying files, taking one package wholesale and dropping another. The merged result is correct, so integration testing passes; the individual PR is not. | A branch deleted `validateCapabilityScopes` from three store chokepoints introduced by the PR below it. |
| **Content without ancestry** | The branch has the right *files* but the branch below is not in its history, so the PR diff re-adds code another PR already adds. | A "merge" that was a file-level copy; `git merge-base --is-ancestor` failed. |
| **Enforcement drift** | The same rule expressed in two places (Go and SQL, boundary and constraint) diverges as one side changes. | Scope filtering in Go vs the SQL `LIKE` queries. |

## Step 1 — Write down the topology

Before diffing anything, state explicitly which branch is based on which, and
which are independent. Get this from git, not from what an agent said:

```bash
for b in <candidate-branches>; do
  echo "$b: base=$(git merge-base --fork-point main "$b" 2>/dev/null || git merge-base main "$b")"
done
```

For every claimed parent relationship, prove it:

```bash
git merge-base --is-ancestor <lower-branch> <upper-branch> && echo ANCESTOR || echo "NOT AN ANCESTOR"
```

`NOT AN ANCESTOR` on a branch that claims to build on another means the merge was
a file-level copy. Fix it with a real `git merge` onto a fresh branch, then
confirm the PR diff no longer contains the lower branch's package.

## Step 2 — Justify every deletion against the branch below

For each stacked branch:

```bash
git diff <lower-branch> <upper-branch> -- <shared-paths>
```

Read the `-` lines. **Every deletion needs a reason.** A deleted validation call,
a deleted error return, a deleted `if` — these are the shape the defect takes, and
they are invisible in a diff against `main` because the code being deleted was
never on `main`.

If the branch introduced a named enforcement chokepoint anywhere in the stack,
grep for it on every branch above:

```bash
git grep -n '<enforcement-symbol>' <upper-branch> -- backend/
```

Absent where it should be present is the finding.

## Step 3 — Find the shared surface and compare implementations directly

List files and symbols touched by more than one branch:

```bash
for b in <candidate-branches>; do git diff --name-only main..$b; done | sort | uniq -d
```

For each shared file, read the actual competing implementations side by side —
`git show <branch-a>:<path>` against `git show <branch-b>:<path>`. Do not compare
test results, and do not ask whether both suites are green: **green suites are
what hide a semantic fork**, because each branch's tests were written to match
that branch's semantics and the divergent cases were simply never written down.

For each divergence, build the truth table by hand — every combination of the
inputs that distinguish the two rules — and check which cells each branch's tests
actually cover. The empty cells are the fork.

## Step 4 — Both artifacts must be correct

There are two artifacts and reviewers judge different ones:

- **The merged result** — what ships, what integration tests exercise.
- **Each branch as its own PR diff** — what a human reviewer reads.

"Merged-result-correct but per-PR-wrong" is a real failure state, not a
technicality. Check both explicitly and say which one any claim refers to.

## Step 5 — Test the combination, not the parts

Merge the candidate stack onto a scratch branch and run the full suite there, from
a clean database:

```bash
git checkout -b scratch/integration-<date> main
git merge --no-ff <branch-1> <branch-2> ...   # resolve conflicts by union, reading both sides
```

Then the project's real validation: `mise exec -- go vet ./...`, `go build ./...`,
`go test -p 1 ./...` with `DATABASE_URL` built from the *configured* password, plus
the sqlc drift check after any change under `internal/store/queries/`. Frontend:
`bun run lint`, `bun run build`, `bun run test`.

Expect conflicts in `go.mod`/`go.sum`/lockfiles when two branches each add a
dependency. That conflict is a **union**, not a choice — take both, and prove it
builds rather than assuming.

The scratch branch is disposable. It exists to prove the combination, not to ship.

## Step 6 — Check for enforcement drift

Where one rule is expressed in two languages or two layers, verify they still
agree, and that any claimed separation actually holds. If a Go-side check and a
SQL-side filter are both said to enforce the same property, either prove the two
can never see the same inputs (and write down *why*, in code) or apply the
deletion test: enforcement exists once, and any second copy must change politeness
only, never possibility.

## Read the artifact, not the report

Every defect in the table above was found by reading git, and at least one was
*hidden* by trusting a report. Two agents once contradicted each other about
whether a security control existed; both were correct, about different artifacts,
and only `git diff` between them resolved it — and in resolving it exposed the
real defect neither had named.

So: before relaying any claim that would change what ships, check it yourself, and
tell the operator which you are relaying — what you verified, or what you were
told. On any workflow or agent failure, `git branch` and `git log` before assuming
the work was lost; agents routinely commit correct work and then fail only at
reporting it.

## Output

A short verdict per pair of branches that share a surface: **agrees**, **diverges
(with the specific case)**, or **deletes (with the specific symbol)**. Plus one
line on whether the combination builds and tests green from a clean database. Do
not report per-branch suite results as evidence about the combination — that is
the exact substitution this skill exists to prevent.
