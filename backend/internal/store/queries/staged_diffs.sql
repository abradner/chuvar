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
INSERT INTO staged_diffs (subject, content, proposed_scopes, target_fact_id, dedupe_verdict, dedupe_candidate_fact_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, subject, content, proposed_scopes, target_fact_id, status, dedupe_verdict, dedupe_candidate_fact_id, created_at;

-- name: GetStagedDiff :one
SELECT id, subject, content, proposed_scopes, target_fact_id, status,
       dedupe_verdict, dedupe_candidate_fact_id, created_at, decided_at, decided_by
FROM staged_diffs WHERE id = $1;

-- name: ListStagedDiffs :many
SELECT id, subject, content, proposed_scopes, target_fact_id, status,
       dedupe_verdict, dedupe_candidate_fact_id, created_at, decided_at, decided_by
FROM staged_diffs WHERE status = $1 ORDER BY created_at ASC;

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
