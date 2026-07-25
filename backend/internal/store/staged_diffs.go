package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/abradner/chuvar/backend/internal/store/sqlcgen"
)

// dedupeCosineThreshold is the cosine-distance cutoff below which a candidate fact
// is considered close enough to flag. This is a placeholder heuristic, not a real
// classifier — see the package comment on embed.Stub. A near match that ISN'T an
// exact text match gets flagged as a contradiction candidate rather than guessed at
// as a duplicate: we can't yet distinguish "paraphrase of the same fact" from "an
// actual conflicting update" without real semantics, and flagging for human review
// is the safe default when we can't tell (Notion §4/§7) — never silently merge.
const dedupeCosineThreshold = 0.15

// ProposeDiff stages a new fact proposal and runs the dedupe check against existing
// active facts before returning. It never writes to `facts` directly — see
// AGENTS.md §3.1; only CommitDiff does that, and only for an approved diff.
//
// proposerGrantedScopes is the proposing subject's current granted scopes — used
// two ways:
//   - The dedupe candidate search only considers facts covered by these scopes
//     (see findDedupeCandidate). Without this, an ungranted agent could propose
//     guessed sensitive content and distinguish "duplicate"/"contradiction" from
//     "novel" via the returned verdict, then reuse the leaked candidate fact ID as
//     targetFactID — a confidentiality leak through a side channel that isn't the
//     read path at all. Found in review.
//   - If targetFactID is set, it must be covered by these scopes too: a proposer
//     can only target a fact they can already read. Without this, an agent could
//     supply an arbitrary fact UUID (guessed, brute-forced, or leaked exactly as
//     above) as a supersession target, and — since the approval UI now surfaces
//     the target's current content (internal/api's getFact / the frontend) — a
//     human reviewer would at least see the replacement, but this check stops the
//     proposal from ever being staged in the first place. Also found in review.
func (s *Store) ProposeDiff(ctx context.Context, subject, content string, scopes []string, embedding []float32, targetFactID *string, proposerGrantedScopes []string) (StagedDiff, error) {
	if content == "" {
		return StagedDiff{}, fmt.Errorf("store: diff content must not be empty")
	}
	if len(scopes) == 0 {
		return StagedDiff{}, fmt.Errorf("store: diff must include at least one scope")
	}

	if targetFactID != nil {
		visible, err := s.factVisibleToScopes(ctx, *targetFactID, proposerGrantedScopes)
		if err != nil {
			return StagedDiff{}, err
		}
		if !visible {
			return StagedDiff{}, fmt.Errorf("store: target_fact_id %s is not covered by the proposer's granted scopes", *targetFactID)
		}
	}

	verdict, candidateID, err := s.findDedupeCandidate(ctx, content, embedding, proposerGrantedScopes)
	if err != nil {
		return StagedDiff{}, err
	}
	var candidate *string
	if candidateID != "" {
		candidate = &candidateID
	}
	verdictStr := string(verdict)

	row, err := s.q.InsertStagedDiff(ctx, sqlcgen.InsertStagedDiffParams{
		Subject:               subject,
		Content:               content,
		ProposedScopes:        scopes,
		TargetFactID:          targetFactID,
		DedupeVerdict:         &verdictStr,
		DedupeCandidateFactID: candidate,
	})
	if err != nil {
		return StagedDiff{}, fmt.Errorf("store: insert staged diff: %w", err)
	}

	d := StagedDiff{
		ID:                    row.ID,
		Subject:               row.Subject,
		Content:               row.Content,
		ProposedScopes:        row.ProposedScopes,
		TargetFactID:          row.TargetFactID,
		Status:                DiffStatus(row.Status),
		DedupeCandidateFactID: row.DedupeCandidateFactID,
		CreatedAt:             row.CreatedAt,
	}
	if row.DedupeVerdict != nil {
		dv := DedupeVerdict(*row.DedupeVerdict)
		d.DedupeVerdict = &dv
	}
	return d, nil
}

// factVisibleToScopes reports whether the active fact id is covered by
// grantedScopes, using the same intersection semantics as SearchFacts'
// candidate_facts CTE (every one of the fact's scope tags must be covered). A fact
// that no longer exists or is already superseded is not visible.
func (s *Store) factVisibleToScopes(ctx context.Context, id string, grantedScopes []string) (bool, error) {
	if len(grantedScopes) == 0 {
		return false, nil
	}
	prefixes := scopePrefixes(grantedScopes)
	visible, err := s.q.FactVisibleToScopes(ctx, sqlcgen.FactVisibleToScopesParams{
		FactID:        id,
		GrantedScopes: grantedScopes,
		ScopePrefixes: prefixes,
	})
	if err != nil {
		return false, fmt.Errorf("store: check fact visibility: %w", err)
	}
	return visible, nil
}

// findDedupeCandidate looks for the nearest active fact by cosine distance, among
// facts covered by grantedScopes only — see ProposeDiff's doc comment for why an
// unfiltered search here is a confidentiality leak, not just a dedupe nicety. An
// empty embedding (caller has no Embedder configured) skips the check entirely and
// reports novel — that's a degraded mode, not a silent failure, since the caller
// chose not to provide one.
func (s *Store) findDedupeCandidate(ctx context.Context, content string, embedding []float32, grantedScopes []string) (DedupeVerdict, string, error) {
	if len(embedding) == 0 || len(grantedScopes) == 0 {
		return DedupeNovel, "", nil
	}

	embParam, err := toVectorParam(embedding)
	if err != nil {
		return "", "", err
	}
	prefixes := scopePrefixes(grantedScopes)

	row, err := s.q.FindDedupeCandidate(ctx, sqlcgen.FindDedupeCandidateParams{
		Embedding1:    *embParam,
		GrantedScopes: grantedScopes,
		ScopePrefixes: prefixes,
		Embedding2:    *embParam,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DedupeNovel, "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("store: dedupe candidate search: %w", err)
	}

	switch {
	case row.Content == content:
		return DedupeDuplicate, row.ID, nil
	case row.Distance.Float64 < dedupeCosineThreshold:
		return DedupeContradiction, row.ID, nil
	default:
		return DedupeNovel, "", nil
	}
}

// GetStagedDiff fetches a single diff by ID. Used by the approval UI's REST API to
// re-embed a diff's content at approval time — see CommitDiff's doc comment on why
// the embedding isn't persisted on the diff row itself.
func (s *Store) GetStagedDiff(ctx context.Context, id string) (StagedDiff, error) {
	row, err := s.q.GetStagedDiff(ctx, id)
	if err != nil {
		return StagedDiff{}, fmt.Errorf("store: get staged diff %s: %w", id, err)
	}
	return toStagedDiff(row), nil
}

// ListStagedDiffs returns diffs in the given status, oldest first (review queue
// order) — used by the approval UI's REST API.
func (s *Store) ListStagedDiffs(ctx context.Context, status DiffStatus) ([]StagedDiff, error) {
	rows, err := s.q.ListStagedDiffs(ctx, string(status))
	if err != nil {
		return nil, fmt.Errorf("store: list staged diffs: %w", err)
	}
	var diffs []StagedDiff
	for _, r := range rows {
		diffs = append(diffs, toStagedDiff(r))
	}
	return diffs, nil
}

func toStagedDiff(row sqlcgen.StagedDiff) StagedDiff {
	d := StagedDiff{
		ID:                    row.ID,
		Subject:               row.Subject,
		Content:               row.Content,
		ProposedScopes:        row.ProposedScopes,
		TargetFactID:          row.TargetFactID,
		Status:                DiffStatus(row.Status),
		DedupeCandidateFactID: row.DedupeCandidateFactID,
		CreatedAt:             row.CreatedAt,
		DecidedAt:             row.DecidedAt,
		DecidedBy:             row.DecidedBy,
	}
	if row.DedupeVerdict != nil {
		dv := DedupeVerdict(*row.DedupeVerdict)
		d.DedupeVerdict = &dv
	}
	return d
}

// RejectDiff marks a pending diff rejected. Never touches `facts`. decidedBy is
// logged to audit_log atomically with the rejection.
func (s *Store) RejectDiff(ctx context.Context, diffID, decidedBy string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if already committed
	qtx := s.q.WithTx(tx)

	db := decidedBy
	rows, err := qtx.RejectDiff(ctx, sqlcgen.RejectDiffParams{ID: diffID, DecidedBy: &db})
	if err != nil {
		return fmt.Errorf("store: reject diff: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("store: diff %s is not pending", diffID)
	}

	if err := logAudit(ctx, qtx, "diff_rejected", decidedBy, nil, nil, &diffID, nil); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit diff rejection: %w", err)
	}
	return nil
}

// CommitDiff is the only path that ever inserts into `facts`. It approves and
// materializes a pending diff in one atomic transaction: insert the fact + its
// scopes, soft-invalidate the superseded fact if this diff targets one (never
// hard-delete — see the migration comment on bi-temporal columns), and mark the
// diff committed. v0 collapses "approve" and "commit" into a single human action;
// the schema keeps `approved` as a distinct status from `committed` so a later
// version can split them (e.g. batched commits) without a schema change.
func (s *Store) CommitDiff(ctx context.Context, diffID, decidedBy string, embedding []float32) (Fact, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Fact{}, fmt.Errorf("store: begin commit tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if already committed
	qtx := s.q.WithTx(tx)

	diff, err := qtx.LoadStagedDiffForUpdate(ctx, diffID)
	if err != nil {
		return Fact{}, fmt.Errorf("store: load staged diff %s: %w", diffID, err)
	}
	if diff.Status != string(DiffPending) {
		return Fact{}, fmt.Errorf("store: diff %s is not pending (status=%s)", diffID, diff.Status)
	}

	// The dedupe verdict was computed once, at ProposeDiff time. Two identical
	// proposals can both be staged as "novel" (neither sees the other, since
	// neither has committed yet) and later both reach CommitDiff — re-checking
	// only at staging time would let both become real, duplicate facts. Re-run
	// the exact-content check here, inside this transaction, right before
	// inserting. This narrows the race to genuinely concurrent commits (the
	// window between this check and the INSERT below) rather than closing it
	// completely — full closure would need a database-level uniqueness
	// constraint, which doesn't compose cleanly with the supersession CHECK
	// constraint below without real complexity. Flagged as a follow-up, not done
	// here: a large jump in complexity for a race that's already far narrower
	// than the original bug (no re-check at all).
	dupExists, err := qtx.HasActiveDuplicateContent(ctx, sqlcgen.HasActiveDuplicateContentParams{
		Content:        diff.Content,
		ExcludeFactID1: diff.TargetFactID,
		ExcludeFactID2: diff.TargetFactID,
	})
	if err != nil {
		return Fact{}, fmt.Errorf("store: duplicate content check: %w", err)
	}
	if dupExists {
		return Fact{}, fmt.Errorf("store: an active fact with identical content already exists; re-review before committing diff %s", diffID)
	}

	embParam, err := toVectorParam(embedding)
	if err != nil {
		return Fact{}, err
	}

	factRow, err := qtx.InsertFact(ctx, sqlcgen.InsertFactParams{
		Content:            diff.Content,
		Embedding:          embParam,
		SourceStagedDiffID: diffID,
	})
	if err != nil {
		return Fact{}, fmt.Errorf("store: insert committed fact: %w", err)
	}

	for _, sc := range diff.ProposedScopes {
		if err := qtx.InsertFactScope(ctx, sqlcgen.InsertFactScopeParams{FactID: factRow.ID, Scope: sc}); err != nil {
			return Fact{}, fmt.Errorf("store: insert fact scope %q: %w", sc, err)
		}
	}

	f := Fact{ID: factRow.ID, Content: factRow.Content, Scopes: diff.ProposedScopes, CreatedAt: factRow.CreatedAt, ValidAt: factRow.ValidAt}

	if diff.TargetFactID != nil {
		// Lock the target fact row before checking/setting its supersession state.
		// Without this, two diffs racing to commit against the same target fact
		// could both pass an unlocked "WHERE invalid_at IS NULL" check, both
		// UPDATE, and both get marked committed — silently losing one
		// supersession link with no error raised (exactly the kind of silent
		// partial failure AGENTS.md §6 forbids in the write/audit path). FOR
		// UPDATE serializes the two transactions: the second one blocks here
		// until the first commits, then re-reads the now-current invalid_at and
		// correctly detects the conflict instead of racing past it.
		targetInvalidAt, err := qtx.LockTargetFact(ctx, *diff.TargetFactID)
		if err != nil {
			return Fact{}, fmt.Errorf("store: lock target fact %s: %w", *diff.TargetFactID, err)
		}
		if targetInvalidAt != nil {
			return Fact{}, fmt.Errorf("store: target fact %s was already superseded by another diff", *diff.TargetFactID)
		}

		if err := qtx.SupersedeFact(ctx, sqlcgen.SupersedeFactParams{
			InvalidAt:    pgtype.Timestamptz{Time: f.ValidAt, Valid: true},
			SupersededBy: &f.ID,
			TargetID:     *diff.TargetFactID,
		}); err != nil {
			return Fact{}, fmt.Errorf("store: supersede target fact %s: %w", *diff.TargetFactID, err)
		}
	}

	db := decidedBy
	if err := qtx.MarkDiffCommitted(ctx, sqlcgen.MarkDiffCommittedParams{ID: diffID, DecidedBy: &db}); err != nil {
		return Fact{}, fmt.Errorf("store: mark diff committed: %w", err)
	}

	if err := logAudit(ctx, qtx, "diff_committed", decidedBy, &f.ID, nil, &diffID, diff.ProposedScopes); err != nil {
		return Fact{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Fact{}, fmt.Errorf("store: commit staged diff %s: %w", diffID, err)
	}
	return f, nil
}
