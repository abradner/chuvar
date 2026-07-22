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

	"memoryvault/internal/embed"
	"memoryvault/internal/scope"
	"memoryvault/internal/store"
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
// scopes. This means a careless or compromised agent can currently mistag a fact's
// scope — the real classifier (once built) is what's meant to catch that; until
// then, human review at approval time is the only backstop, which is one more
// reason the "no direct writes" rule (AGENTS.md §3.1) isn't optional.
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
	scopes := proposedScopes
	classified, err := b.Classifier.Classify(ctx, content)
	if err != nil {
		return store.StagedDiff{}, fmt.Errorf("bouncer: classify: %w", err)
	}
	if len(classified) > 0 {
		scopes = classified
	}
	if len(scopes) == 0 {
		return store.StagedDiff{}, fmt.Errorf("bouncer: no scopes proposed or classified for content")
	}
	for _, sc := range scopes {
		if err := scope.Validate(sc); err != nil {
			return store.StagedDiff{}, fmt.Errorf("bouncer: %w", err)
		}
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
