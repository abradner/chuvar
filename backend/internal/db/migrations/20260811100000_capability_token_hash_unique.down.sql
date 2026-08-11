-- Reverts to the non-unique index 20260809140000_capability_grant_signing
-- originally created.
--
-- There is no data to restore: the up migration never deletes token rows
-- and never revokes grants. On a duplicate token hash it refuses to apply
-- at all and hands the decision to the operator (see its own comment, and
-- docs/operations.md, "Duplicate capability token hashes"), precisely so
-- that no migration silently exercises authority or erases evidence.
--
-- What rolling back does mean: the table can go ambiguous again — two
-- grants may once more share a token hash, and a credential that derives
-- more than one grant has ambiguous scope, committer identity and audit
-- attribution. That is the state the up migration exists to make
-- impossible.
DROP INDEX IF EXISTS capability_grant_tokens_hash_idx;
CREATE INDEX capability_grant_tokens_hash_idx ON capability_grant_tokens (token_hash);
