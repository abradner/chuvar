-- Agent-class tokens (ticket E3, PR 1 of 3): the credential mcpserver will
-- eventually hold in place of a raw database connection (AGENTS.md §3.6,
-- "the residual gap"). This migration only adds the table, store methods,
-- and a human-gated mint/list/revoke HTTP surface — mcpserver itself is
-- untouched until a later PR switches it from a DB credential to this
-- token.
--
-- The invariant this table exists to hold: an agent-class token must be a
-- structurally distinct credential from a reviewer token. It lives in its
-- own table, keyed by its own hash column, so AuthenticateReviewerToken's
-- lookup against reviewer_tokens can never match one — there is no shared
-- namespace for a leaked or injected agent token to be presented against
-- the reviewer surface and accepted. Mirrors reviewer_tokens
-- (20260726010000_reviewer_tokens.up.sql) in shape and the partial-unique-
-- index convention it settled on (20260726030000_reviewer_tokens_partial_
-- unique.up.sql) rather than reviewer_tokens' original (buggy) plain-UNIQUE
-- column: a global UNIQUE(token_hash) would mean a revoked row still
-- occupies its hash forever, which the reviewer_tokens fix's own comment
-- explains is the wrong bar. Rotation here (revoke old, mint new) is
-- already the intended pattern per the subject/label split below, so a
-- fresh 32-byte random token colliding with its own revoked predecessor's
-- hash is not a realistic recovery scenario the way REVIEWER_BOOTSTRAP_
-- TOKEN reuse is for reviewer_tokens — but there is no reason to
-- reintroduce a known-wrong pattern just because the collision case is
-- rarer here.
--
-- subject and label are deliberately separate columns. subject is the
-- grant/audit identity — the value a grant's `subject` column and every
-- audit_log row this token's holder produces will carry — while label is
-- pure operator-facing description ("mcpserver-prod", "mcpserver-laptop").
-- Keeping them apart means a token can be rotated (revoke the old row,
-- mint a new one with the same subject) without orphaning the grants and
-- audit history that reference that subject: subject is what persists
-- across a rotation, label is what changes to describe the new physical
-- credential.
CREATE TABLE agent_tokens (
    id           UUID PRIMARY KEY DEFAULT uuidv7(),
    subject      TEXT NOT NULL,
    label        TEXT NOT NULL,
    token_hash   BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

-- Active-token lookup is the hot path (every authenticated agent request,
-- once mcpserver adopts this in a later PR) — a partial unique index means
-- the query never has to look at revoked history, and uniqueness only
-- holds among currently-active rows, matching reviewer_tokens' repaired
-- design rather than its original one.
CREATE UNIQUE INDEX agent_tokens_active_hash_idx ON agent_tokens (token_hash) WHERE revoked_at IS NULL;

-- Deliberately no GRANT statements here. 20260803000000_least_privilege_
-- roles.up.sql's ALTER DEFAULT PRIVILEGES already grants every new table to
-- chuvar_app (apiserver's role — this is exactly the table apiserver's new
-- HTTP surface needs to read and write) and grants nothing to
-- chuvar_agent/chuvar_broker. Confirmed by reading that migration: it ends
-- with "New tables should default to invisible to the agent and be widened
-- only on purpose." That default is the policy for this table too — an
-- agent-side process (mcpserver, or anything else running as chuvar_agent)
-- must not be able to read or write its own credential's table, mint
-- itself a replacement, or read another token's hash. Nothing in this PR
-- widens chuvar_agent's grants, and nothing should until a PR explicitly
-- decides mcpserver needs to touch this table directly (it shouldn't: it
-- will authenticate through apiserver, not read agent_tokens itself).
