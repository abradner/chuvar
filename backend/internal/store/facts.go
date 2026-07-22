package store

import (
	"context"
	"fmt"

	"github.com/pgvector/pgvector-go"
)

// rrfK is the standard Reciprocal Rank Fusion smoothing constant (Cormack et al.'s
// original RRF paper uses 60; it's not sensitive to small changes, no need to make
// it configurable yet).
const rrfK = 60

// SearchFacts runs the hybrid retrieval query: keyword (tsvector) and semantic
// (pgvector cosine) rankings fused via Reciprocal Rank Fusion, over only the facts
// whose scope tags are ALL covered by grantedScopes. The scope filter runs in the
// candidate_facts CTE, before either ranking happens — ungranted facts never enter
// the ranked candidate set. This is the security property described in AGENTS.md
// §3.2 and validated against prior art in the Notion mining writeup (§7): filtering
// after ranking (as a pluggable-external-vector-store path would do) is exactly the
// anti-pattern this design avoids.
//
// An empty grantedScopes returns no results — no grant means no access, not "search
// everything and filter later."
func (s *Store) SearchFacts(ctx context.Context, queryText string, queryEmbedding []float32, grantedScopes []string, limit int) ([]Fact, error) {
	if len(grantedScopes) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 20
	}

	prefixes := make([]string, len(grantedScopes))
	for i, g := range grantedScopes {
		prefixes[i] = g + ".%"
	}

	rows, err := s.pool.Query(ctx, searchFactsSQL,
		grantedScopes,
		prefixes,
		queryText,
		pgvector.NewVector(queryEmbedding),
		rrfK,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("store: search facts: %w", err)
	}
	defer rows.Close()

	var facts []Fact
	for rows.Next() {
		var f Fact
		var score float64
		if err := rows.Scan(&f.ID, &f.Content, &f.CreatedAt, &f.ValidAt, &f.Scopes, &score); err != nil {
			return nil, fmt.Errorf("store: scan fact: %w", err)
		}
		facts = append(facts, f)
	}
	return facts, rows.Err()
}

const searchFactsSQL = `
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
            AND NOT (fs.scope = ANY($1) OR fs.scope LIKE ANY($2))
      )
),
keyword_ranked AS (
    SELECT f.id, row_number() OVER (ORDER BY ts_rank(f.content_tsv, plainto_tsquery('english', $3)) DESC) AS rank
    FROM facts f
    JOIN candidate_facts c ON c.id = f.id
    WHERE f.content_tsv @@ plainto_tsquery('english', $3)
),
vector_ranked AS (
    SELECT f.id, row_number() OVER (ORDER BY f.embedding <=> $4) AS rank
    FROM facts f
    JOIN candidate_facts c ON c.id = f.id
    WHERE f.embedding IS NOT NULL
)
SELECT
    f.id,
    f.content,
    f.created_at,
    f.valid_at,
    (SELECT array_agg(fs.scope) FROM fact_scopes fs WHERE fs.fact_id = f.id) AS scopes,
    COALESCE(1.0 / ($5 + k.rank), 0) + COALESCE(1.0 / ($5 + v.rank), 0) AS score
FROM candidate_facts c
JOIN facts f ON f.id = c.id
LEFT JOIN keyword_ranked k ON k.id = c.id
LEFT JOIN vector_ranked v ON v.id = c.id
WHERE k.id IS NOT NULL OR v.id IS NOT NULL
ORDER BY score DESC
LIMIT $6
`
