package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
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

// GetFact fetches a single active or superseded fact by ID. Used by the approval
// UI's REST API to show what a staged diff's target_fact_id actually is before a
// human approves — the reviewer should see the content being replaced, not just
// an opaque UUID. No scope filtering here: this is a reviewer-facing lookup keyed
// by an ID the reviewer already has from a staged diff they're actively deciding
// on (internal/api's shared-token auth is what gates who can reach this at all),
// not a search endpoint that needs to hide facts a caller hasn't been granted.
func (s *Store) GetFact(ctx context.Context, id string) (Fact, error) {
	row, err := s.q.GetFact(ctx, id)
	if err != nil {
		return Fact{}, fmt.Errorf("store: get fact %s: %w", id, err)
	}
	return Fact{ID: row.ID, Content: row.Content, Scopes: row.Scopes, CreatedAt: row.CreatedAt, ValidAt: row.ValidAt}, nil
}

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

	qt := queryText
	rows, err := s.q.SearchFacts(ctx, sqlcgen.SearchFactsParams{
		RrfK1:           pgtype.Int8{Int64: rrfK, Valid: true},
		RrfK2:           pgtype.Int8{Int64: rrfK, Valid: true},
		ResultLimit:     pgtype.Int8{Int64: int64(limit), Valid: true},
		GrantedScopes:   grantedScopes,
		ScopePrefixes:   prefixes,
		QueryText:       &qt,
		QueryEmbedding1: embParam,
		QueryEmbedding2: embParam,
	})
	if err != nil {
		return nil, fmt.Errorf("store: search facts: %w", err)
	}

	var facts []Fact
	for _, r := range rows {
		facts = append(facts, Fact{ID: r.ID, Content: r.Content, Scopes: r.Scopes, CreatedAt: r.CreatedAt, ValidAt: r.ValidAt})
	}
	return facts, nil
}
