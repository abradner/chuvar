// Package bouncer implements the write-path pipeline behind propose_write:
// classify → embed → dedupe → stage. It never commits a fact — see AGENTS.md §3.1.
// Approval/commit and rejection are separate, human-triggered actions (store.
// CommitDiff, store.RejectDiff), not part of this package.
//
// This is a plain Go pipeline for v0, not a Temporal workflow, per AGENTS.md §3.3 —
// a deliberate, documented two-way door, not an oversight.
package bouncer

import (
	"context"
	"fmt"
	"time"

	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/scope"
	"github.com/abradner/chuvar/backend/internal/store"
)

// Classifier proposes scope tags for a piece of content. Interface + stub for the
// same reason as embed.Embedder: real classification is unbuilt research work
// (Notion: "Research — Scope Classifier & Dedup Model"), not yet available to wire
// in, but already known to need a second (real) implementation later.
type Classifier interface {
	// Classify returns the scopes it believes content belongs to, or nil to defer
	// to the caller-proposed scopes verbatim. nil and an empty-but-non-nil slice
	// are NOT the same thing: nil means "no opinion, use the caller's scopes,"
	// while a non-nil empty slice is a real (if unusual) classification of "no
	// scopes apply" and overrides the caller's proposal rather than deferring to
	// it. Implementations must return actual nil, not a zero-length slice, to defer.
	Classify(ctx context.Context, content string) ([]scope.Scope, error)
}

// PassthroughClassifier is the v0 stub: it never overrides the caller-proposed
// scopes. Scope tags are what read_with_scope_check filters on at retrieval time —
// they ARE the access-control boundary (AGENTS.md §3.2) — so trusting the proposer's
// own tags with no cross-check is a real confidentiality risk, not a labeling
// nicety: a compromised or careless agent could propose a sensitive fact tagged
// with an unrelated, broadly-granted scope (e.g. a real name or health detail
// tagged "preferences.coffee" instead of something under "identity"), and if a
// human reviewer approves it — plausible, since there's no fixed taxonomy yet
// (§3.4) to sanity-check the tag against — it becomes readable by anyone holding
// that broad, commonly-granted scope. The real classifier (once built) is what's
// meant to catch that; until then, careful human review at approval time is the
// only backstop, which is one more reason the "no direct writes" rule (§3.1) isn't
// optional.
type PassthroughClassifier struct{}

func (PassthroughClassifier) Classify(_ context.Context, _ string) ([]scope.Scope, error) {
	return nil, nil
}

// defaultRateLimit and defaultRateLimitWindow are New's fallback for
// RateLimit/RateLimitWindow — a generous but non-zero default, so a caller that
// doesn't wire config.Config's PROPOSE_WRITE_RATE_LIMIT* values through still
// gets a working limit rather than an accidental zero (which
// store.CheckProposeWriteRateLimit treats as a misconfiguration error, not
// "unlimited" — see that method's doc comment on why zero must fail closed).
const (
	defaultRateLimit       = 20
	defaultRateLimitWindow = time.Minute
)

type Bouncer struct {
	Store      *store.Store
	Embedder   embed.Embedder
	Classifier Classifier

	// RateLimit and RateLimitWindow bound how many ProposeWrite calls a single
	// subject may make per window before it starts returning
	// store.ErrRateLimited — see that method's doc comment for the mechanism
	// and CLAUDE.md's ticket ("propose_write requires no grant at all — the
	// review queue is spammable") for why this exists. New sets both to a
	// sane default; override after construction (e.g. from config.Config) to
	// tune them.
	RateLimit       int
	RateLimitWindow time.Duration
}

func New(s *store.Store, e embed.Embedder, c Classifier) *Bouncer {
	return &Bouncer{
		Store:           s,
		Embedder:        e,
		Classifier:      c,
		RateLimit:       defaultRateLimit,
		RateLimitWindow: defaultRateLimitWindow,
	}
}

// ProposeWrite runs the pipeline for one proposed fact and returns the staged
// diff, including the dedupe verdict the store computed. targetFactID, if set,
// means this proposal claims to update/supersede an existing fact.
func (b *Bouncer) ProposeWrite(ctx context.Context, subject, content string, proposedScopes []scope.Scope, targetFactID *string) (store.StagedDiff, error) {
	// store.ProposeDiff rejects empty content anyway, but only after this function
	// has already paid for classification and embedding — both meant to become
	// real (external, costly) calls. Reject up front instead.
	//
	// This is a genuine caller-input failure — the proposing agent can fix it and
	// retry — so it's a ValidationError, not a plain wrapped error: see that
	// type's doc comment for why propose_write is allowed to show it verbatim.
	if content == "" {
		return store.StagedDiff{}, newValidationError("bouncer: content must not be empty")
	}

	// Validate the caller's input before doing any work on its behalf — in
	// particular before calling Classify, which is a stub today but is meant to
	// become a real (likely external/costly) call; no reason to pay that for a
	// request that was always going to be rejected as malformed. Same
	// ValidationError reasoning as the empty-content check above: this is the
	// caller's own scope string, not anything derived from the classifier or
	// store.
	for _, sc := range proposedScopes {
		if err := scope.Validate(sc); err != nil {
			return store.StagedDiff{}, newValidationError("bouncer: %s", err)
		}
	}

	if b.Classifier == nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: misconfigured: nil Classifier")
	}
	if b.Store == nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: misconfigured: nil Store")
	}

	// Rate-limit after the cheap caller-input validation above but before
	// Classify and Embed: this subject may hold zero grants (propose_write
	// deliberately requires none, so a brand-new agent can still propose
	// before it's been granted anything — see the propose_write_rate_limit
	// migration for the full threat this guards against) and still be able to
	// flood the human review queue for free. Both Classify and Embed are stubs
	// today but are meant to become real external, costly calls — checking the
	// limit only after them would let an over-limit subject keep generating
	// unbounded provider traffic and cost while every request comes back
	// RATE_LIMITED and stages nothing. Found in aggregate review.
	if err := b.Store.CheckProposeWriteRateLimit(ctx, subject, b.RateLimit, b.RateLimitWindow); err != nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: %w", err)
	}

	scopes := proposedScopes
	classified, err := b.Classifier.Classify(ctx, content)
	if err != nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: classify: %w", err)
	}
	// nil vs. non-nil-empty matters here (see Classifier's doc comment): only nil
	// means "defer to the caller." A classifier that deliberately returns "no
	// scopes apply" as a non-nil empty slice must be able to override the caller,
	// not have that override silently discarded.
	if classified != nil {
		for _, sc := range classified {
			if err := scope.Validate(sc); err != nil {
				// Deliberately NOT a ValidationError: this scope came from the
				// Classifier, not from the calling agent's own input, so it isn't
				// something the agent can fix by resubmitting — it's this
				// service's own component misbehaving. Fail closed and mask it
				// like any other internal failure rather than assume it's safe.
				return store.StagedDiff{}, fmt.Errorf("bouncer: classifier produced invalid scope: %w", err)
			}
		}
		scopes = classified
	}
	scopes = scope.Dedupe(scopes)
	if len(scopes) == 0 {
		// Reachable via either an empty caller-supplied proposedScopes (with the
		// classifier deferring) or a classifier override to "no scopes apply" —
		// either way the message itself names no store/driver internals and is
		// actionable ("propose at least one scope"), so it's safe as a
		// ValidationError even though the root cause isn't always the caller.
		return store.StagedDiff{}, newValidationError("bouncer: no scopes proposed or classified for content")
	}

	if b.Embedder == nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: misconfigured: nil Embedder")
	}
	vec, err := b.Embedder.Embed(ctx, content)
	if err != nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: embed: %w", err)
	}

	scopeStrs := make([]string, len(scopes))
	for i, sc := range scopes {
		scopeStrs[i] = string(sc)
	}

	// The subject's current granted scopes gate both the dedupe candidate search
	// and target_fact_id visibility inside ProposeDiff — see that function's doc
	// comment. Fetched here rather than inside the store layer because Bouncer
	// already owns "what does this subject need to act" plumbing (Embedder,
	// Classifier); Store just persists what it's handed.
	grantedScopes, err := b.Store.GrantedScopes(ctx, subject)
	if err != nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: granted scopes: %w", err)
	}
	diff, err := b.Store.ProposeDiff(ctx, subject, content, scopeStrs, vec, targetFactID, grantedScopes)
	if err != nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: stage diff: %w", err)
	}
	return diff, nil
}
