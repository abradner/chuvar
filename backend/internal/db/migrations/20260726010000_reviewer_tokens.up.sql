-- Reviewer device tokens: replaces the single shared API_AUTH_TOKEN (internal/api's
-- original v0 auth) with named, individually revocable per-device/per-reviewer
-- tokens. This is the first concrete step on the "decided_by/approved_by/revoked_by
-- are self-reported, not authenticated" gap (Notion tasks tracker) — those fields
-- are derived from the authenticated token's label from here on, not read from the
-- request body.
--
-- Only the token's SHA-256 hash is stored, never the plaintext — same reasoning as
-- requireAuth's existing constant-time comparison: a stolen database dump shouldn't
-- hand out live credentials. Labels are operator-chosen free text ("alex-laptop",
-- "tui-pi5"), not a fixed enum, matching the project's general "don't invent a
-- taxonomy before there's a reason to" stance (AGENTS.md §3.4 on scopes applies to
-- the same instinct here).
CREATE TABLE reviewer_tokens (
    id          UUID PRIMARY KEY DEFAULT uuidv7(),
    label       TEXT NOT NULL,
    token_hash  BYTEA NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);

-- Active-token lookup is the hot path (every authenticated request) — partial index
-- means the query never has to look at revoked history.
CREATE INDEX reviewer_tokens_active_hash_idx ON reviewer_tokens (token_hash) WHERE revoked_at IS NULL;
