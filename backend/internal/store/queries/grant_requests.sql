-- name: InsertGrantRequest :one
INSERT INTO grant_requests (subject, requested_scopes, depth, requested_ttl_seconds, justification)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, subject, requested_scopes, depth, requested_ttl_seconds, justification, status, created_at, decided_at, decided_by, resulting_grant_id;

-- name: GetGrantRequest :one
SELECT id, subject, requested_scopes, depth, requested_ttl_seconds, justification, status, created_at, decided_at, decided_by, resulting_grant_id
FROM grant_requests WHERE id = $1;

-- name: ListGrantRequests :many
SELECT id, subject, requested_scopes, depth, requested_ttl_seconds, justification, status, created_at, decided_at, decided_by, resulting_grant_id
FROM grant_requests WHERE status = $1 ORDER BY created_at ASC;

-- name: LoadGrantRequestForUpdate :one
SELECT subject, requested_scopes, depth, requested_ttl_seconds, status FROM grant_requests WHERE id = $1 FOR UPDATE;

-- name: ApproveGrantRequest :execrows
UPDATE grant_requests
SET status = 'approved', decided_at = now(), decided_by = $2, resulting_grant_id = $3
WHERE id = $1 AND status = 'pending';

-- name: DenyGrantRequest :execrows
UPDATE grant_requests SET status = 'denied', decided_at = now(), decided_by = $2
WHERE id = $1 AND status = 'pending';
