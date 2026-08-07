package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/abradner/chuvar/backend/internal/scope"
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
// whose scope tags are ALL covered by some scope in granted. The scope filter runs
// in the candidate_facts CTE, before either ranking happens — ungranted facts never
// enter the ranked candidate set. This is the security property described in
// AGENTS.md §3.2 and validated against prior art in the Notion mining writeup (§7):
// filtering after ranking (as a pluggable-external-vector-store path would do) is
// exactly the anti-pattern this design avoids.
//
// Each returned Fact's Depth and Content/Summary are set by effectiveDepth,
// computed from granted's per-scope depths against that fact's own scope tags —
// this is a disclosure projection over rows that already passed the scope filter
// above, not a second visibility filter, so it doesn't reintroduce the
// filter-after-ranking anti-pattern §3.2 warns against: every fact in candidate_facts
// is still returned, just with Content redacted to Summary at "summary" depth.
//
// Only the summary/{facts,full} split is projected here. "full" is meant to add
// a fact's *provenance* to its content (the init migration's "progressive
// disclosure per Notion §3": summary → facts → full provenance), which this
// query does not yet select — see mcptools.factView's doc comment for the
// columns involved and why that level is worth keeping distinct.
//
// Depth is enforced on THIS read path only. It is not a system-wide chokepoint,
// and describing it as one would be wrong: findDedupeCandidate (staged_diffs.go,
// reached via propose_write) is a second content-disclosure surface that is
// scope-filtered but not depth-filtered, so a summary-depth holder can still use
// its "duplicate" verdict as a guess-and-confirm oracle over exact content this
// function would have redacted. Verified, tracked separately — see that
// function's doc comment.
//
// An empty granted returns no results — no grant means no access, not "search
// everything and filter later."
func (s *Store) SearchFacts(ctx context.Context, queryText string, queryEmbedding []float32, granted []GrantedScope, limit int) ([]Fact, error) {
	if len(granted) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 20
	}

	grantedScopes := make([]string, len(granted))
	for i, g := range granted {
		grantedScopes[i] = g.Scope
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
		depth, err := effectiveDepth(r.Scopes, granted)
		if err != nil {
			return nil, fmt.Errorf("store: search facts: %w", err)
		}
		f := Fact{ID: r.ID, Scopes: r.Scopes, CreatedAt: r.CreatedAt, ValidAt: r.ValidAt, Depth: depth}
		if depth == "summary" {
			// Fail closed on NULL (pre-migration or not-yet-summarized facts):
			// Summary stays "" rather than falling back to Content, which would
			// silently un-enforce the redaction this depth exists to apply.
			if r.Summary != nil {
				f.Summary = *r.Summary
			}
		} else {
			f.Content = r.Content
		}
		facts = append(facts, f)
	}
	return facts, nil
}

// effectiveDepth computes the depth a fact should be read at, given the fact's own
// scope tags and the caller's granted (scope, depth) pairs. Composition mirrors the
// two rules internal/scope already encodes rather than inventing a third: grants
// union across a subject's scopes (scope.AnyCovers — a scope is granted if ANY
// active grant covers it, per GrantedScopes' own doc comment), while a fact's tags
// compose as an intersection (scope.Satisfied — every tag must be covered). So for
// each of the fact's tags, take the MOST permissive depth among grants covering
// that tag (a tag can be covered by more than one active grant — union); then take
// the LEAST permissive of those per-tag results across the fact's tags
// (intersection), since a fact is one indivisible blob: a broadly-granted
// unrelated tag must not pull full content out of a fact that also carries a tag
// only granted at summary depth.
//
// Union-across-grants for a single tag (rather than most-recent-wins) matches how
// scope visibility itself already behaves: a stale broad-depth grant already
// confers read access at all, which is strictly worse than conferring it at
// greater depth, and the system's designed remedy for a stale grant is
// revocation/TTL (both audited), not a silent precedence rule a reviewer can't
// see. The caller surfaces the result as Fact.Depth so this is observable per
// fact, not silent.
//
// factScopes with a tag no covering grant is found for shouldn't happen — SQL's
// candidate_facts CTE already guarantees every tag is covered by some granted
// scope before a fact reaches here — but fails closed to "summary" rather than
// assuming "full" if it ever does. An error return means a granted depth or a
// computed rank fell outside the closed vocabulary (see grants.go's depthRank
// and depthName) — unreachable today given the DB CHECK constraint, but the
// caller must deny rather than guess a permissiveness level in that case.
func effectiveDepth(factScopes []string, granted []GrantedScope) (string, error) {
	best := -1
	for _, tag := range factScopes {
		tagRank := -1
		for _, g := range granted {
			if scope.Scope(g.Scope).Covers(scope.Scope(tag)) {
				r, err := depthRank(g.Depth)
				if err != nil {
					return "", err
				}
				if r > tagRank {
					tagRank = r
				}
			}
		}
		if tagRank == -1 {
			return "summary", nil
		}
		if best == -1 || tagRank < best {
			best = tagRank
		}
	}
	if best == -1 {
		return "summary", nil
	}
	return depthName(best)
}
