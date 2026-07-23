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

	"chuvar/internal/embed"
	"chuvar/internal/scope"
	"chuvar/internal/store"
)

// Classifier proposes scope tags for a piece of content. Interface + stub for the
// same reason as embed.Embedder: real classification is unbuilt research work
// (Notion: "Research — Scope Classifier & Dedup Model"), not yet available to wire
// in, but already known to need a second (real) implementation later.
type Classifier interface {
	// Classify returns the scopes it believes content belongs to, or nil to defer
	// to the caller-proposed scopes verbatim.
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

type Bouncer struct {
	Store      *store.Store
	Embedder   embed.Embedder
	Classifier Classifier
}

func New(s *store.Store, e embed.Embedder, c Classifier) *Bouncer {
	return &Bouncer{Store: s, Embedder: e, Classifier: c}
}

// ProposeWrite runs the pipeline for one proposed fact and returns the staged
// diff, including the dedupe verdict the store computed. targetFactID, if set,
// means this proposal claims to update/supersede an existing fact.
func (b *Bouncer) ProposeWrite(ctx context.Context, subject, content string, proposedScopes []scope.Scope, targetFactID *string) (store.StagedDiff, error) {
	// Validate the caller's input before doing any work on its behalf — in
	// particular before calling Classify, which is a stub today but is meant to
	// become a real (likely external/costly) call; no reason to pay that for a
	// request that was always going to be rejected as malformed.
	for _, sc := range proposedScopes {
		if err := scope.Validate(sc); err != nil {
			return store.StagedDiff{}, fmt.Errorf("bouncer: %w", err)
		}
	}

	scopes := proposedScopes
	classified, err := b.Classifier.Classify(ctx, content)
	if err != nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: classify: %w", err)
	}
	if len(classified) > 0 {
		for _, sc := range classified {
			if err := scope.Validate(sc); err != nil {
				return store.StagedDiff{}, fmt.Errorf("bouncer: classifier produced invalid scope: %w", err)
			}
		}
		scopes = classified
	}
	if len(scopes) == 0 {
		return store.StagedDiff{}, fmt.Errorf("bouncer: no scopes proposed or classified for content")
	}

	vec, err := b.Embedder.Embed(ctx, content)
	if err != nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: embed: %w", err)
	}

	scopeStrs := make([]string, len(scopes))
	for i, sc := range scopes {
		scopeStrs[i] = string(sc)
	}

	diff, err := b.Store.ProposeDiff(ctx, subject, content, scopeStrs, vec, targetFactID)
	if err != nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: stage diff: %w", err)
	}
	return diff, nil
}
