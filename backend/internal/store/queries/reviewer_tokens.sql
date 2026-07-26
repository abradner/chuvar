-- name: InsertReviewerToken :one
INSERT INTO reviewer_tokens (label, token_hash)
VALUES ($1, $2)
RETURNING id, label, created_at;

-- name: LookupActiveReviewerToken :one
SELECT id, label FROM reviewer_tokens
WHERE token_hash = $1 AND revoked_at IS NULL;

-- name: TouchReviewerToken :exec
UPDATE reviewer_tokens SET last_used_at = now() WHERE id = $1;

-- name: ListReviewerTokens :many
SELECT id, label, created_at, last_used_at, revoked_at FROM reviewer_tokens ORDER BY created_at ASC;

-- name: RevokeReviewerToken :execrows
UPDATE reviewer_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: CountActiveReviewerTokens :one
SELECT count(*) FROM reviewer_tokens WHERE revoked_at IS NULL;
