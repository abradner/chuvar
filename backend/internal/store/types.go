// Package store is the only place in this codebase that writes SQL. Every other
// package (MCP tools, the bouncer, the REST API) goes through Store rather than
// touching pgxpool.Pool directly.
package store

import "time"

// GrantKind discriminates what a grant governs. Introduced so grants/
// grant_requests/audit_log — one consent primitive (subject, scopes, TTL,
// revocation, audit) — can be reused for the Agent Capability Broker
// workstream's capabilities (git commit signing first) without a second,
// parallel schema. depth is meaningful only for KindMemory; see the
// grant_kind migration's doc comment for the DB-level invariant.
type GrantKind string

const (
	GrantKindMemory     GrantKind = "memory"
	GrantKindCapability GrantKind = "capability"
)

type Grant struct {
	ID      string
	Subject string
	Scopes  []string
	Kind    GrantKind
	// Depth is empty for anything other than KindMemory — there is no
	// equivalent concept for a capability grant. Kept as a plain string
	// (empty-string sentinel) rather than *string to match how "" already
	// meant "unset" at the API/mcptools boundary before this type existed.
	Depth     string
	CreatedAt time.Time
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

// Active reports whether the grant is currently usable: not revoked, and not past
// its expiry (grants with no expiry are open-ended).
func (g Grant) Active(now time.Time) bool {
	if g.RevokedAt != nil {
		return false
	}
	if g.ExpiresAt != nil && now.After(*g.ExpiresAt) {
		return false
	}
	return true
}

type DedupeVerdict string

const (
	DedupeNovel         DedupeVerdict = "novel"
	DedupeDuplicate     DedupeVerdict = "duplicate"
	DedupeContradiction DedupeVerdict = "contradiction"
)

type DiffStatus string

const (
	DiffPending   DiffStatus = "pending"
	DiffApproved  DiffStatus = "approved"
	DiffRejected  DiffStatus = "rejected"
	DiffCommitted DiffStatus = "committed"
)

type StagedDiff struct {
	ID                    string
	Subject               string
	Content               string
	ProposedScopes        []string
	TargetFactID          *string
	Status                DiffStatus
	DedupeVerdict         *DedupeVerdict
	DedupeCandidateFactID *string
	CreatedAt             time.Time
	DecidedAt             *time.Time
	DecidedBy             *string
}

type Fact struct {
	ID string
	// Content and Summary are mutually exclusive projections of the fact,
	// selected by Depth: SearchFacts sets exactly one of them, matching the
	// depth of the grant(s) that authorized this read (see facts.go's
	// effectiveDepth). GetFact (the reviewer-facing, unfiltered lookup) sets
	// Content only and leaves Depth empty — there's no grant/depth concept on
	// that path.
	Content   string
	Summary   string
	Depth     string
	Scopes    []string
	CreatedAt time.Time
	ValidAt   time.Time
	// Provenance is set only when Depth == "full" (see facts.go's SearchFacts
	// loop) — nil at "summary" or "facts" depth, mirroring how Content/Summary
	// are already mutually exclusive by Depth above. GetFact never sets it,
	// same reason its Depth is always empty.
	Provenance *FactProvenance
}

// FactProvenance is a fact's approval trail, supersession pointer, and
// bi-temporal validity window — the content this codebase means by "full
// provenance" (init migration's "progressive disclosure per Notion §3":
// summary -> facts -> full provenance). Every field here already exists on
// facts/staged_diffs; this struct just names the projection of it that "full"
// depth is meant to add on top of a fact's content. Disclosing DecidedBy is
// exactly why this is its own depth level above "facts": it names a human,
// which the fact's content alone never does.
type FactProvenance struct {
	// SourceStagedDiffID traces to the staged_diffs row whose approval produced
	// this fact (facts.source_staged_diff_id — NOT NULL on every committed fact).
	SourceStagedDiffID string
	// DecidedBy/DecidedAt are that staged diff's approval trail. Nil only if
	// the source diff is somehow undecided, which shouldn't happen for a
	// committed fact but isn't assumed impossible by this type.
	DecidedBy *string
	DecidedAt *time.Time
	// SupersededBy points at the fact that replaced this one, if any — part of
	// the append-only supersession chain (CLAUDE.md principle 12).
	SupersededBy *string
	// InvalidAt/ExpiredAt complete the bi-temporal pair alongside the Fact's own
	// CreatedAt/ValidAt: InvalidAt is when the fact stopped being true in the
	// world (event time), ExpiredAt is when Chuvar recorded that (system time).
	// Both nil for a still-current fact — facts_supersession_consistency (init
	// migration) guarantees they're set together with SupersededBy.
	InvalidAt *time.Time
	ExpiredAt *time.Time
}

// GrantedScope pairs a granted scope with the depth of the grant that covers
// it, for depth-aware reads (SearchFacts). Unlike GrantedScopes' flat deduped
// []string, this can return more than one entry per scope: the backing query
// (GrantedScopeDepths) is DISTINCT on (scope, depth), not scope alone, so two
// active grants covering the same scope at different depths each produce
// their own row. SearchFacts needs exactly that — every covering grant's
// depth, not just one of them — to compute an effective depth per fact (see
// facts.go's effectiveDepth). What it does NOT do is collapse two grants that
// happen to share both the same scope and the same depth; those are
// legitimately indistinguishable for this purpose and the DISTINCT collapses
// them into one row. Found in review.
type GrantedScope struct {
	Scope string
	Depth string
}

// ListCursor is a page boundary for the cursor-paginated listing methods
// (ListStagedDiffsPage, ListGrantsPage): the (created_at, id) of the last row
// the caller has already seen. nil means "first page." Keyed on created_at/id
// together, not an offset — the tables these methods page over gain and lose
// rows continuously while a reviewer is working (new staged diffs/grants
// arriving, an existing one being approved/rejected/revoked), and offset
// pagination silently skips or repeats rows across that churn; a keyset
// comparison against the last row actually returned doesn't, since it isn't a
// row count. id breaks ties between rows sharing a created_at — see
// ListStagedDiffsPage's doc comment (staged_diffs.go) for why created_at
// alone isn't a safe total order here.
type ListCursor struct {
	CreatedAt time.Time
	ID        string
}
