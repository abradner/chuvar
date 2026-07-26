-- Found in review (Copilot + Codex P2, on the followup PR that added the
-- corresponding up migration): the up migration's whole point is to let
-- revoked tokens share a hash with a later active one (the break-glass
-- recovery path this table exists to support). Blindly reintroducing a
-- global UNIQUE(token_hash) here would fail with a cryptic duplicate-key
-- error the moment that scenario has actually happened — precisely the
-- state this migration is most likely to be rolled back FROM. A clear,
-- actionable error beats a cryptic constraint-violation one.
DO $$
BEGIN
    IF EXISTS (
        SELECT token_hash FROM reviewer_tokens GROUP BY token_hash HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot roll back 20260726030000_reviewer_tokens_partial_unique: reviewer_tokens has rows sharing a token_hash (expected once a revoked token has been reused via the break-glass bootstrap flow — see cmd/apiserver''s bootstrapReviewerToken). Resolve the duplicates manually (e.g. delete the stale revoked rows) before reintroducing the global UNIQUE constraint.';
    END IF;
END $$;

DROP INDEX reviewer_tokens_active_hash_idx;
CREATE INDEX reviewer_tokens_active_hash_idx ON reviewer_tokens (token_hash) WHERE revoked_at IS NULL;
ALTER TABLE reviewer_tokens ADD CONSTRAINT reviewer_tokens_token_hash_key UNIQUE (token_hash);
