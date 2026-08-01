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
}

// GrantedScope pairs a granted scope with the depth of the grant that covers
// it, for depth-aware reads (SearchFacts). Unlike GrantedScopes' flat
// deduped []string, this doesn't collapse multiple covering grants into one
// entry — SearchFacts needs every covering grant's depth to compute an
// effective depth per fact (facts.go's effectiveDepth), since a subject can
// hold more than one active grant over the same or overlapping scope at
// different depths.
type GrantedScope struct {
	Scope string
	Depth string
}
