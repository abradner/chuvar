-- Reverts to the non-unique index 20260809140000_capability_grant_signing
-- originally created. This does NOT restore any capability_grant_tokens
-- rows the up migration deleted, nor un-revoke any grant it force-revoked
-- — deletion and revocation are not undone by a down migration any more
-- than 20260726030000_reviewer_tokens_partial_unique.down.sql restores
-- reviewer_tokens rows it never touched. If a deployment actually hit the
-- duplicate-token-hash case, rolling back returns the table to "can go
-- ambiguous again," not to how it looked before the up migration ran.
DROP INDEX IF EXISTS capability_grant_tokens_hash_idx;
CREATE INDEX capability_grant_tokens_hash_idx ON capability_grant_tokens (token_hash);
