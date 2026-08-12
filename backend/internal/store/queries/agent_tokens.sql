-- name: InsertAgentToken :one
INSERT INTO agent_tokens (subject, label, token_hash)
VALUES ($1, $2, $3)
RETURNING id, subject, label, created_at;

-- name: LookupActiveAgentToken :one
SELECT id, subject, label FROM agent_tokens
WHERE token_hash = $1 AND revoked_at IS NULL;

-- name: TouchAgentToken :exec
UPDATE agent_tokens SET last_used_at = now() WHERE id = $1;

-- name: ListAgentTokens :many
SELECT id, subject, label, created_at, last_used_at, revoked_at FROM agent_tokens ORDER BY created_at ASC;

-- name: RevokeAgentToken :execrows
UPDATE agent_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;
