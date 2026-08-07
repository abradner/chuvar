-- name: InsertGrant :one
INSERT INTO grants (subject, kind, depth, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id, subject, depth, created_at, expires_at, revoked_at, kind;

-- name: InsertGrantScope :exec
INSERT INTO grant_scopes (grant_id, scope) VALUES ($1, $2);

-- name: ListGrants :many
-- Scopes come back via an array_agg subquery (same shape as
-- ListGrantsNearingExpiry and GetFact/SearchFacts' fact_scopes aggregation)
-- rather than a separate ListGrantScopes call per row — avoids an N+1 that
-- scales with (grants for subject) per call. Found in review.
SELECT id, subject, depth, created_at, expires_at, revoked_at, kind,
       (SELECT array_agg(gs.scope) FROM grant_scopes gs WHERE gs.grant_id = grants.id)::text[] AS scopes
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

-- name: RenewGrant :one
-- Only a currently-active grant (not revoked, not already past its expiry) can
-- be renewed — zero rows affected (surfaced by sqlc as pgx.ErrNoRows for a
-- :one query) covers "doesn't exist," "already revoked," and "already
-- expired" alike; store.RenewGrant turns that into one clear error.
--
-- kind = 'memory' is deliberate, not incidental. Renewal was built for memory
-- grants, and extending a *capability* grant is a materially different act:
-- capability renewal has to answer what happens to key material held for the
-- grant's duration, whether the custody backend must be reachable to renew,
-- and whether a renewal is a fresh authorization decision rather than a date
-- change. None of that is designed yet. Until the broker answers it, a
-- capability grant is renewed by not being renewable — deliberately, rather
-- than inheriting memory's semantics by omission. Nothing can create one
-- today (both API and MCP hardcode kind='memory'), so this filter is a latch
-- closed before the door exists, not a live fix.
UPDATE grants SET expires_at = $2
WHERE id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
  AND kind = 'memory'
RETURNING id, subject, depth, created_at, expires_at, revoked_at, kind;

-- name: ListGrantsNearingExpiry :many
-- Subject-agnostic by design, like ListStagedDiffs/ListGrantRequests — v0 is a
-- single-operator system (AGENTS.md), so the expiry-warning SSE stream isn't
-- scoped per subject either.
--
-- Scopes come back via an array_agg subquery (same shape as GetFact/
-- SearchFacts' fact_scopes aggregation in facts.sql) rather than a separate
-- ListGrantScopes call per row: this query runs from the /api/events poll
-- loop, potentially every eventPollInterval per connected SSE client, so an
-- N+1 pattern here scales with (expiring grants) x (connected clients) x
-- (polls/sec) — worth avoiding at the query level rather than in a hot loop.
-- Found in review.
SELECT g.id, g.subject, g.depth, g.created_at, g.expires_at, g.revoked_at, g.kind,
       (SELECT array_agg(gs.scope) FROM grant_scopes gs WHERE gs.grant_id = g.id)::text[] AS scopes
FROM grants g
WHERE g.revoked_at IS NULL
  AND g.expires_at IS NOT NULL
  AND g.expires_at > now()
  AND g.expires_at <= $1
ORDER BY g.expires_at ASC;
