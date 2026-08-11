-- name: UpsertSigningPolicy :one
-- One row per repo: a second upsert for the same repo replaces the previous
-- policy and set_by rather than erroring, matching how a reviewer actually
-- changes their mind about a policy (set again, not "unset then set"). The
-- audit trail for who changed it and when lives in audit_log, written by
-- store.UpsertSigningPolicy in the same transaction — this row only ever
-- reflects the current value.
INSERT INTO signing_policies (repo, policy, set_by)
VALUES ($1, $2, $3)
ON CONFLICT (repo) DO UPDATE
SET policy = EXCLUDED.policy, set_by = EXCLUDED.set_by, updated_at = now()
RETURNING repo, policy, set_by, created_at, updated_at;

-- name: GetSigningPolicy :one
SELECT repo, policy, set_by, created_at, updated_at FROM signing_policies WHERE repo = $1;
