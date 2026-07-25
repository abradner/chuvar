package store

import (
	"context"
	"fmt"
	"strings"
)

// likeEscaper escapes Postgres LIKE metacharacters (and the escape character
// itself) in a literal string, using LIKE's default escape character (backslash).
// scope.Validate allows `_` in scope segments — e.g. "identity.date_of_birth" — but
// Postgres LIKE treats an unescaped `_` as "match any one character." Without this,
// a granted scope containing `_` would silently widen the WHERE-clause scope filter
// beyond what was actually granted (e.g. "projects_alpha.%" would also match
// "projectsXalpha.secret" for any character X) — a real boundary-widening bug this
// escapes, not a defensive nicety.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `_`, `\_`, `%`, `\%`)

// scopePrefixes converts grantedScopes into LIKE patterns that match a scope's
// dotted descendants (e.g. "projects.spritz" -> "projects.spritz.%"), escaping
// LIKE metacharacters. Shared by SearchFacts and findDedupeCandidate — both need
// identical scope-visibility semantics, since the dedupe candidate search is a
// second read path with the same confidentiality requirement as search: a fact
// outside the caller's grants must not be observable through it either.
func scopePrefixes(grantedScopes []string) []string {
	prefixes := make([]string, len(grantedScopes))
	for i, g := range grantedScopes {
		prefixes[i] = likeEscaper.Replace(g) + ".%"
	}
	return prefixes
}

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

	prefixes := scopePrefixes(grantedScopes)

	embParam, err := toVectorParam(queryEmbedding)
	if err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(ctx, searchFactsSQL,
		grantedScopes,
		prefixes,
		queryText,
		embParam,
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

// GetFact fetches a single active or superseded fact by ID. Used by the approval
// UI's REST API to show what a staged diff's target_fact_id actually is before a
// human approves — the reviewer should see the content being replaced, not just
// an opaque UUID. No scope filtering here: this is a reviewer-facing lookup keyed
// by an ID the reviewer already has from a staged diff they're actively deciding
// on (internal/api's shared-token auth is what gates who can reach this at all),
// not a search endpoint that needs to hide facts a caller hasn't been granted.
func (s *Store) GetFact(ctx context.Context, id string) (Fact, error) {
	var f Fact
	err := s.pool.QueryRow(ctx,
		`SELECT f.id, f.content, f.created_at, f.valid_at,
		        (SELECT array_agg(fs.scope) FROM fact_scopes fs WHERE fs.fact_id = f.id) AS scopes
		 FROM facts f WHERE f.id = $1`,
		id,
	).Scan(&f.ID, &f.Content, &f.CreatedAt, &f.ValidAt, &f.Scopes)
	if err != nil {
		return Fact{}, fmt.Errorf("store: get fact %s: %w", id, err)
	}
	return f, nil
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
    -- $4 IS NOT NULL guards keyword-only mode (no query embedding available):
    -- without it, every row would still get a rank from a NULL-vs-vector comparison
    -- instead of contributing zero rows to this CTE, which would corrupt the RRF
    -- fusion below. The explicit ::vector cast (on both uses of $4) isn't optional —
    -- without it Postgres can't determine $4's type at prepare time once it appears
    -- in a plain IS NOT NULL context alongside the <=> operator context, and errors
    -- with "could not determine data type of parameter" before any value is bound.
    SELECT f.id, row_number() OVER (ORDER BY f.embedding <=> $4::vector) AS rank
    FROM facts f
    JOIN candidate_facts c ON c.id = f.id
    WHERE f.embedding IS NOT NULL AND $4::vector IS NOT NULL
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
