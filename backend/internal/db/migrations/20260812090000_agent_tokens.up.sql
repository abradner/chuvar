-- Agent-class tokens (ticket E3, PR 1 of the workstream): the credential
-- cmd/mcpserver will hold once it stops being a raw database connection and
-- becomes an API client instead. This migration builds only the credential
-- itself — schema, store methods, and the human-gated mint/list/revoke HTTP
-- surface. mcpserver is untouched; it still holds DATABASE_URL until a later
-- PR in this workstream actually switches it over.
--
-- Structurally distinct from reviewer_tokens, on purpose (AGENTS.md CLAUDE.md
-- principle 3, zero ambient authority; principle 4, "no agent-reachable path
-- mints ... authority"): an agent-class token lives in its own table, in its
-- own hash space, so it can never be looked up by AuthenticateReviewerToken's
-- query and therefore can never pass reviewer authentication no matter what
-- value it takes. Mirrors reviewer_tokens' shape and conventions closely
-- (20260726010000_reviewer_tokens.up.sql, 20260726030000_reviewer_tokens_
-- partial_unique.up.sql) — same hashed-storage discipline, same partial
-- unique index over active rows only, for the same break-glass-reuse reason
-- reviewer_tokens' partial-unique migration documents.
--
-- subject and label are deliberately two different columns, not one:
--   * subject is the grant/audit identity — what CreateGrant/audit_log's
--     "subject" column key authority to. Rotating a token (revoke the old
--     row, mint a new one with the SAME subject) must not orphan any grant
--     issued to that subject.
--   * label is operator-facing free text ("laptop-agent-1", "ci-runner") for
--     telling tokens apart in the list UI, exactly like reviewer_tokens.label
--     — it carries no authority and is never read by any authorization check.
CREATE TABLE agent_tokens (
    id           UUID PRIMARY KEY DEFAULT uuidv7(),
    subject      TEXT NOT NULL,
    label        TEXT NOT NULL,
    token_hash   BYTEA NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

-- Active-token lookup is the hot path (every authenticated agent request, once
-- something calls AuthenticateAgentToken) — partial index means the query
-- never has to scan revoked history. Built as a UNIQUE partial index directly
-- (not a global UNIQUE constraint narrowed by a follow-up migration, the way
-- reviewer_tokens did it in two steps) since this table starts from nothing:
-- there's no pre-existing global constraint to migrate away from, so there's
-- no reason to introduce one just to immediately replace it. Uniqueness only
-- needs to hold among active rows — two revoked rows (or a revoked row and a
-- fresh active one) sharing a hash is harmless, matching reviewer_tokens'
-- documented break-glass-reuse rationale.
CREATE UNIQUE INDEX agent_tokens_active_hash_idx ON agent_tokens (token_hash) WHERE revoked_at IS NULL;

-- Deliberately no GRANT lines here. ALTER DEFAULT PRIVILEGES IN SCHEMA public
-- (20260803000000_least_privilege_roles.up.sql) already grants every new
-- table to chuvar_app automatically, and — by the same default-privileges
-- statement's own doc comment — NEVER to chuvar_agent or chuvar_broker
-- ("chuvar_agent is granted automatically, chuvar_agent is NOT ... widening
-- either role's view is always a deliberate act"). Verified directly: `ALTER
-- DEFAULT PRIVILEGES ... TO` appears in exactly one migration
-- (20260803000000_least_privilege_roles.up.sql) and names only chuvar_app —
-- never chuvar_agent, never chuvar_broker. Some later migrations DO grant
-- chuvar_agent narrow, explicit column-level access to specific tables it
-- actually calls (e.g. 20260808000000_propose_write_rate_limit.up.sql,
-- 20260804000000_agent_staged_diffs_decision_columns.up.sql) — those are
-- deliberate, one at a time, for tables mcpserver's code path touches.
-- agent_tokens gets no such line, and mcpserver has no reason to ever read
-- it: this table exists to let apiserver mint/revoke *the token mcpserver
-- will eventually hold*, not for mcpserver to query about itself. So
-- neither chuvar_agent nor chuvar_broker gets SELECT here — even the
-- process holding an agent-class token cannot read the hash table it's a
-- row in, let alone another agent's row. Only chuvar_app (apiserver, the
-- only binary that mints/lists/revokes these tokens per this PR's brief)
-- can touch this table at all.
