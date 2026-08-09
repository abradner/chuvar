-- Per-repository git-commit-signing policy (issue #94; the policy-home half
-- of issue #72, resolved in the 2026-08-09 decision log entry "Signing policy
-- lives broker-side, in the consent plane," docs/capability-broker.md).
--
-- One row per repository identifier, keyed on the bare repo string (the
-- target half of a capability scope like `git.sign:github.com/abradner/chuvar`,
-- per the 2026-08-09 scope-grammar decision) rather than a scope value:
-- nothing here depends on internal/scope's colon-target grammar landing, which
-- is still unbuilt. What IS enforced today: internal/api's validateRepo
-- canonicalizes-or-rejects the repo to that bare target form — lowercase host,
-- host/owner/repo shape, no URL scheme, no `.git` suffix, no trailing slash, no
-- `..` segment — on both the write and the read path, so a `required` policy
-- can never be set under one spelling and evaded under a divergent one. That
-- canonicalization is API-layer only; the column below is a plain TEXT PRIMARY
-- KEY with no CHECK for the shape (unlike policy, which has both), so validateRepo
-- is its sole enforcement. Full repo-identifier grammar unification with
-- internal/scope's target validation is tracked in issue #98.
--
-- policy is a closed vocabulary — required/preferred/off — and the CHECK
-- constraint below is the enforcement (AGENTS.md §6's deletion test):
-- internal/api validates the same three values before an insert/update ever
-- reaches this table, but that's legibility (a clean 400 instead of a raw
-- constraint-violation 500 leaking out of the driver), not a second
-- enforcement point. Deleting either check must only ever change how a bad
-- value is reported, never whether a fourth value can land in the column.
--
-- A checked-in policy file (e.g. `.chuvar/signing-policy`) was explicitly
-- rejected as the enforcement surface for this decision: it would be
-- agent-writable by construction — an agent with worktree write access could
-- flip `required` to `off` itself, which is the bypass ratchet in file form,
-- and violates "an agent can request a grant; an agent cannot change
-- policy" (CLAUDE.md principle 4). This table, reachable only through
-- apiserver's reviewer-authenticated, TOTP-gated REST surface (never from
-- mcpserver or any agent-reachable path), is that surface instead.
--
-- set_by is who set the *current* row — the authenticated reviewer token's
-- label (internal/api's reviewerFromContext, never a request-body field),
-- the same provenance discipline as grants.*_by throughout this schema. It's
-- overwritten on every upsert, same as updated_at: this table holds current
-- state only, one row per repo. The full history of who changed what, when,
-- and from what previous value lives in audit_log (one row per change,
-- append-only), not here — same split as every other mutable table in this
-- schema versus its audit trail.
CREATE TABLE signing_policies (
    repo        TEXT PRIMARY KEY,
    policy      TEXT NOT NULL CHECK (policy IN ('required', 'preferred', 'off')),
    set_by      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Deliberately no GRANT here for chuvar_agent. This is human-set
-- consent-plane data, read and written only by apiserver — chuvar_app gets
-- full DML on it automatically via the least_privilege_roles migration's
-- ALTER DEFAULT PRIVILEGES. mcpserver has no code path that touches signing
-- policy today (brokerd, the eventual reader for its own preflight checks,
-- isn't built yet either), and that migration's own stance is that a new
-- table defaults to invisible to the agent — widen chuvar_agent's view only
-- when a real caller needs it, not speculatively.
