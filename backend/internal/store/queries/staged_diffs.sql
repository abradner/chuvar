-- name: FactVisibleToScopes :one
SELECT EXISTS (
    SELECT 1 FROM facts f
    WHERE f.id = @fact_id
      AND f.invalid_at IS NULL
      AND EXISTS (SELECT 1 FROM fact_scopes fs WHERE fs.fact_id = f.id)
      AND NOT EXISTS (
          SELECT 1 FROM fact_scopes fs
          WHERE fs.fact_id = f.id
            AND NOT (fs.scope = ANY(@granted_scopes::text[]) OR fs.scope LIKE ANY(@scope_prefixes::text[]))
      )
) AS visible;

-- name: FindDedupeCandidate :one
-- embedding_1/embedding_2 are the same repeated-named-param workaround used
-- elsewhere in this migration (see facts.sql's SearchFacts) — bound to the
-- identical value at the call site.
SELECT f.id, f.content, f.embedding <=> @embedding_1::vector AS distance
FROM facts f
WHERE f.invalid_at IS NULL AND f.embedding IS NOT NULL
  AND EXISTS (SELECT 1 FROM fact_scopes fs WHERE fs.fact_id = f.id)
  AND NOT EXISTS (
      SELECT 1 FROM fact_scopes fs
      WHERE fs.fact_id = f.id
        AND NOT (fs.scope = ANY(@granted_scopes::text[]) OR fs.scope LIKE ANY(@scope_prefixes::text[]))
  )
ORDER BY f.embedding <=> @embedding_2::vector
LIMIT 1;

-- name: InsertStagedDiff :one
-- Returns only the columns the database generates. Everything else in the row
-- is the caller's own input, so echoing it back is redundant — and it is not
-- free: RETURNING requires SELECT privilege on every column it reads, so a
-- wide RETURNING forced a table-wide SELECT grant for cmd/mcpserver, letting an
-- agent enumerate every other subject's proposed content. Narrow here, and the
-- grant narrows with it (see the least_privilege_roles migration).
INSERT INTO staged_diffs (subject, content, proposed_scopes, target_fact_id, dedupe_verdict, dedupe_candidate_fact_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, status, created_at;

-- name: GetStagedDiff :one
SELECT id, subject, content, proposed_scopes, target_fact_id, status,
       dedupe_verdict, dedupe_candidate_fact_id, created_at, decided_at, decided_by
FROM staged_diffs WHERE id = $1;

-- name: ListStagedDiffsPage :many
-- Cursor-paginated listing for GET /api/staged-diffs (internal/api/
-- staged_diffs.go). Keyed on (created_at, id), not an offset: the pending
-- queue this backs gains rows (new proposals) and loses them (approvals/
-- rejections) continuously while a reviewer works it, and offset pagination
-- silently skips or repeats rows across that churn — a keyset comparison
-- against the last row actually returned doesn't, since it isn't a row
-- count. id breaks ties between rows sharing a created_at (uuidv7 IDs are
-- roughly time-ordered but created_at itself isn't guaranteed distinct down
-- to its own precision) — without it, two same-timestamp rows could be
-- skipped or duplicated across the page boundary, depending on Postgres'
-- otherwise-unspecified tie order. sqlc.narg(cursor_created_at) IS NULL means
-- "first page," matching internal/api's "no cursor" convention.
--
-- LIMIT is bound to limit+1, not limit, by the caller (store.
-- ListStagedDiffsPage) — fetching one extra row is how that caller answers
-- "does another page exist" without a second query.
SELECT id, subject, content, proposed_scopes, target_fact_id, status,
       dedupe_verdict, dedupe_candidate_fact_id, created_at, decided_at, decided_by
FROM staged_diffs
WHERE status = @status
  AND (sqlc.narg(cursor_created_at)::timestamptz IS NULL
       OR (created_at, id) > (sqlc.narg(cursor_created_at)::timestamptz, sqlc.narg(cursor_id)::uuid))
ORDER BY created_at ASC, id ASC
LIMIT @lim;

-- name: ListStagedDiffsBounded :many
-- Explicit-bound (not paginated) listing for the /api/events SSE poll loop
-- (internal/api/events.go's streamEvents): that loop re-runs a status query
-- every eventPollInterval per connected client and needs a snapshot of
-- "currently pending," not a page it resumes across polls — there's no
-- cursor to carry between ticks, only a cap, so a large backlog can't turn a
-- fixed-cadence poll into an unbounded-cost one. Same shape/rationale as
-- ListGrantsNearingExpiry (grants.sql), bounded for the identical reason.
SELECT id, subject, content, proposed_scopes, target_fact_id, status,
       dedupe_verdict, dedupe_candidate_fact_id, created_at, decided_at, decided_by
FROM staged_diffs
WHERE status = @status
ORDER BY created_at ASC
LIMIT @lim;

-- name: RejectDiff :execrows
UPDATE staged_diffs SET status = 'rejected', decided_at = now(), decided_by = $2
WHERE id = $1 AND status = 'pending';

-- name: LoadStagedDiffForUpdate :one
SELECT content, proposed_scopes, target_fact_id, status
FROM staged_diffs WHERE id = $1 FOR UPDATE;

-- name: HasActiveDuplicateContent :one
-- Two distinct named params bound to the identical exclude-fact-ID value at the
-- call site (see staged_diffs.go) — sqlc's parser doesn't handle referencing the
-- same named param twice cleanly in this position (same issue worked around in
-- facts.sql's SearchFacts).
SELECT EXISTS (
    SELECT 1 FROM facts
    WHERE invalid_at IS NULL AND content = @content
      AND (sqlc.narg(exclude_fact_id_1)::uuid IS NULL OR id != sqlc.narg(exclude_fact_id_2))
) AS has_duplicate;

-- name: InsertFact :one
INSERT INTO facts (content, summary, embedding, source_staged_diff_id)
VALUES ($1, $2, $3, $4)
RETURNING id, content, summary, created_at, valid_at;

-- name: InsertFactScope :exec
INSERT INTO fact_scopes (fact_id, scope) VALUES ($1, $2);

-- name: LockTargetFact :one
SELECT invalid_at FROM facts WHERE id = $1 FOR UPDATE;

-- name: SupersedeFact :exec
UPDATE facts SET invalid_at = @invalid_at, expired_at = now(), superseded_by = @superseded_by
WHERE id = @target_id;

-- name: MarkDiffCommitted :exec
UPDATE staged_diffs SET status = 'committed', decided_at = now(), decided_by = $2 WHERE id = $1;
