-- name: GetFact :one
SELECT f.id, f.content, f.created_at, f.valid_at,
       (SELECT array_agg(fs.scope) FROM fact_scopes fs WHERE fs.fact_id = f.id)::text[] AS scopes
FROM facts f WHERE f.id = $1;

-- name: SearchFacts :many
WITH candidate_facts AS (
    -- Scope filter runs here, before any ranking. A fact qualifies only if EVERY
    -- one of its scope tags is covered by some granted scope (intersection
    -- semantics — matches internal/scope.Satisfied) — no fact_scopes row may exist
    -- that isn't covered by an exact match or a dotted-ancestor prefix match.
    SELECT f.id
    FROM facts f
    WHERE f.invalid_at IS NULL
      AND EXISTS (SELECT 1 FROM fact_scopes fs WHERE fs.fact_id = f.id)
      AND NOT EXISTS (
          SELECT 1 FROM fact_scopes fs
          WHERE fs.fact_id = f.id
            AND NOT (fs.scope = ANY(sqlc.arg(granted_scopes)::text[]) OR fs.scope LIKE ANY(sqlc.arg(scope_prefixes)::text[]))
      )
),
keyword_ranked AS (
    SELECT f.id, row_number() OVER (ORDER BY ts_rank(f.content_tsv, plainto_tsquery('english', sqlc.arg(query_text))) DESC) AS rank
    FROM facts f
    JOIN candidate_facts c ON c.id = f.id
    WHERE f.content_tsv @@ plainto_tsquery('english', sqlc.arg(query_text))
),
vector_ranked AS (
    -- Two distinct named params (query_embedding_1/_2) rather than reusing one:
    -- sqlc's parser doesn't handle referencing the same @name/sqlc.arg twice
    -- cleanly inside this particular CTE shape. Both are bound to the identical
    -- Go value at the call site (see facts.go). The ::vector cast on both is
    -- still required regardless — Postgres can't determine either parameter's
    -- type at prepare time once it appears in both an IS NOT NULL context and the
    -- <=> operator context without it.
    SELECT f.id, row_number() OVER (ORDER BY f.embedding <=> sqlc.narg(query_embedding_1)::vector) AS rank
    FROM facts f
    JOIN candidate_facts c ON c.id = f.id
    WHERE f.embedding IS NOT NULL AND sqlc.narg(query_embedding_2)::vector IS NOT NULL
)
SELECT
    f.id,
    f.content,
    f.summary,
    f.created_at,
    f.valid_at,
    (SELECT array_agg(fs.scope) FROM fact_scopes fs WHERE fs.fact_id = f.id)::text[] AS scopes,
    -- Provenance columns for "full" depth (mcptools.factView projects these only
    -- when a fact's effective depth is "full" — see store.SearchFacts). Selected
    -- for every candidate row regardless of depth, same as content/summary above;
    -- the depth gate is applied in Go, once, per AGENTS.md §3.2's "filter before
    -- ranking, not after" — here that's "select once here, gate at the one place
    -- that already computes per-row depth," not a second SQL-level filter to keep
    -- in sync with the first.
    f.source_staged_diff_id,
    f.superseded_by,
    f.invalid_at,
    f.expired_at,
    sd.decided_by,
    sd.decided_at,
    COALESCE(1.0 / (sqlc.arg(rrf_k_1) + k.rank), 0) + COALESCE(1.0 / (sqlc.arg(rrf_k_2) + v.rank), 0) AS score
FROM candidate_facts c
JOIN facts f ON f.id = c.id
LEFT JOIN keyword_ranked k ON k.id = c.id
LEFT JOIN vector_ranked v ON v.id = c.id
-- LEFT JOIN, not JOIN: source_staged_diff_id is NOT NULL and FK-enforced today,
-- so this always matches, but a provenance projection shouldn't be able to drop
-- an otherwise-visible fact from the result set if that ever changes.
LEFT JOIN staged_diffs sd ON sd.id = f.source_staged_diff_id
WHERE k.id IS NOT NULL OR v.id IS NOT NULL
ORDER BY score DESC
LIMIT sqlc.arg(result_limit);
