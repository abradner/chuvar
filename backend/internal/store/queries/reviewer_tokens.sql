-- name: InsertReviewerToken :one
INSERT INTO reviewer_tokens (label, token_hash, totp_secret)
VALUES ($1, $2, $3)
RETURNING id, label, created_at;

-- name: LookupActiveReviewerToken :one
SELECT id, label FROM reviewer_tokens
WHERE token_hash = $1 AND revoked_at IS NULL;

-- name: GetReviewerTOTPSecret :one
SELECT totp_secret FROM reviewer_tokens WHERE id = $1;

-- name: TouchReviewerToken :exec
UPDATE reviewer_tokens SET last_used_at = now() WHERE id = $1;

-- name: ListReviewerTokens :many
SELECT id, label, created_at, last_used_at, revoked_at FROM reviewer_tokens ORDER BY created_at ASC;

-- name: RevokeReviewerToken :execrows
UPDATE reviewer_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: CountActiveReviewerTokens :one
SELECT count(*) FROM reviewer_tokens WHERE revoked_at IS NULL;

-- name: CountEverEnrolledReviewerTokens :one
-- Deliberately NOT filtered on revoked_at: this counts whether a TOTP device
-- has *ever* been enrolled, which is a monotonic, attacker-unlowerable signal.
-- Counting only active tokens made revocation (bearer-only by design, since it
-- "only reduces authority") into an escalation lever: revoke every enrolled
-- device, drop the count to zero, then mint a fresh token and self-enroll
-- through the now-open gate. Revoked rows are never deleted, so this count
-- only ever grows. See createToken (internal/api/tokens.go).
SELECT count(*) FROM reviewer_tokens WHERE totp_secret IS NOT NULL;
