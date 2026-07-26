DROP INDEX reviewer_tokens_active_hash_idx;
CREATE INDEX reviewer_tokens_active_hash_idx ON reviewer_tokens (token_hash) WHERE revoked_at IS NULL;
ALTER TABLE reviewer_tokens ADD CONSTRAINT reviewer_tokens_token_hash_key UNIQUE (token_hash);
