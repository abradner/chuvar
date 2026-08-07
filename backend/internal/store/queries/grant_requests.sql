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

-- name: ListGrantRequestsBounded :many
-- Explicit-bound variant of ListGrantRequests for the /api/events SSE poll
-- loop, same rationale as staged_diffs.sql's ListStagedDiffsBounded. The REST
-- listing endpoint (GET /api/grant-requests, internal/api/grant_requests.go)
-- keeps calling the plain ListGrantRequests above unchanged — pagination for
-- that endpoint isn't this ticket's scope (a separate ticket in the same
-- batch); only its poll-loop caller needed a bound here.
SELECT id, subject, requested_scopes, depth, requested_ttl_seconds, justification, status, created_at, decided_at, decided_by, resulting_grant_id, kind
FROM grant_requests WHERE status = @status ORDER BY created_at ASC LIMIT @lim;

-- name: LoadGrantRequestForUpdate :one
SELECT subject, requested_scopes, depth, requested_ttl_seconds, status, kind FROM grant_requests WHERE id = $1 FOR UPDATE;

-- name: ApproveGrantRequest :execrows
UPDATE grant_requests
SET status = 'approved', decided_at = now(), decided_by = $2, resulting_grant_id = $3
WHERE id = $1 AND status = 'pending';

-- name: DenyGrantRequest :execrows
UPDATE grant_requests SET status = 'denied', decided_at = now(), decided_by = $2
WHERE id = $1 AND status = 'pending';
