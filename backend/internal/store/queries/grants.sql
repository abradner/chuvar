-- name: InsertGrant :one
INSERT INTO grants (subject, kind, depth, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id, subject, depth, created_at, expires_at, revoked_at, kind;

-- name: InsertGrantScope :exec
INSERT INTO grant_scopes (grant_id, scope) VALUES ($1, $2);

-- name: ListGrants :many
SELECT id, subject, depth, created_at, expires_at, revoked_at, kind
FROM grants WHERE subject = $1 ORDER BY created_at DESC;

-- name: ListGrantScopes :many
SELECT scope FROM grant_scopes WHERE grant_id = $1;

-- name: GrantedScopes :many
-- kind = 'memory' excludes capability-only grants (e.g. git.sign:...) from
-- authorizing memory reads/writes over the same scope string — see
-- store.GrantedScopes' doc comment.
SELECT DISTINCT gs.scope
FROM grant_scopes gs
JOIN grants g ON g.id = gs.grant_id
WHERE g.subject = $1
  AND g.kind = 'memory'
  AND g.revoked_at IS NULL
  AND (g.expires_at IS NULL OR g.expires_at > now());

-- name: GrantedScopeDepths :many
-- depth IS NOT NULL is implied by kind = 'memory' (the grants_kind_depth_pairing
-- CHECK constraint), restated here rather than relied on so this query's own
-- WHERE clause is self-documenting independent of that constraint existing
-- elsewhere.
SELECT DISTINCT gs.scope, g.depth
FROM grant_scopes gs
JOIN grants g ON g.id = gs.grant_id
WHERE g.subject = $1
  AND g.kind = 'memory'
  AND g.depth IS NOT NULL
  AND g.revoked_at IS NULL
  AND (g.expires_at IS NULL OR g.expires_at > now());

-- name: RevokeGrant :execrows
UPDATE grants SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;
