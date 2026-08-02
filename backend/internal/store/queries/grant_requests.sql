-- name: InsertGrantRequest :one
-- Database-generated columns only; see InsertStagedDiff for why. The rest is
-- the caller's own input, and returning `justification` in particular meant the
-- agent role needed SELECT over every subject's stated reasons for wanting a
-- grant.
INSERT INTO grant_requests (subject, requested_scopes, kind, depth, requested_ttl_seconds, justification)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, status, created_at;

-- name: GetGrantRequest :one
SELECT id, subject, requested_scopes, depth, requested_ttl_seconds, justification, status, created_at, decided_at, decided_by, resulting_grant_id, kind
FROM grant_requests WHERE id = $1;

-- name: ListGrantRequests :many
SELECT id, subject, requested_scopes, depth, requested_ttl_seconds, justification, status, created_at, decided_at, decided_by, resulting_grant_id, kind
FROM grant_requests WHERE status = $1 ORDER BY created_at ASC;

-- name: LoadGrantRequestForUpdate :one
SELECT subject, requested_scopes, depth, requested_ttl_seconds, status, kind FROM grant_requests WHERE id = $1 FOR UPDATE;

-- name: ApproveGrantRequest :execrows
UPDATE grant_requests
SET status = 'approved', decided_at = now(), decided_by = $2, resulting_grant_id = $3
WHERE id = $1 AND status = 'pending';

-- name: DenyGrantRequest :execrows
UPDATE grant_requests SET status = 'denied', decided_at = now(), decided_by = $2
WHERE id = $1 AND status = 'pending';
