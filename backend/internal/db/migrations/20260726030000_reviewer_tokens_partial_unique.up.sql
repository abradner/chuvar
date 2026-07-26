-- Found in review (Codex, P1): the global UNIQUE(token_hash) constraint on
-- reviewer_tokens survives revocation — a revoked row still occupies its hash
-- in the unique index. That silently breaks the documented break-glass
-- recovery path in cmd/apiserver's bootstrapReviewerToken: if every token
-- gets revoked and the operator restarts with the *same* REVIEWER_BOOTSTRAP_TOKEN
-- value the doc comment tells them to reuse, the insert fails on the
-- now-revoked row's still-live unique entry, and the server can never start.
--
-- Fix: uniqueness only needs to hold among *active* tokens — two revoked rows
-- (or a revoked row and a fresh active one) sharing a hash is harmless, since
-- AuthenticateReviewerToken's lookup already filters on revoked_at IS NULL.
-- Replacing the global unique constraint with a partial unique index that
-- does exactly that also lets it double as the existing active-token lookup
-- index (reviewer_tokens_active_hash_idx) instead of maintaining two indexes
-- over the same column.
ALTER TABLE reviewer_tokens DROP CONSTRAINT reviewer_tokens_token_hash_key;
DROP INDEX reviewer_tokens_active_hash_idx;
CREATE UNIQUE INDEX reviewer_tokens_active_hash_idx ON reviewer_tokens (token_hash) WHERE revoked_at IS NULL;
