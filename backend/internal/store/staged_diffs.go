package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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
//     above) as a supersession target, and — since the approval UI doesn't
//     currently surface what's being replaced (a separate, UI-layer gap) — get a
//     human to unknowingly approve silently invalidating an unrelated fact. Also
//     found in review. This check is necessarily best-effort against a grant that
//     changes between proposal and approval; it's not a substitute for the
//     approval UI showing the target explicitly, which is a real fix in its own
//     right, not just defense in depth.
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

	var d StagedDiff
	var statusStr string
	var scannedVerdict *string
	err = s.pool.QueryRow(ctx,
		`INSERT INTO staged_diffs (subject, content, proposed_scopes, target_fact_id, dedupe_verdict, dedupe_candidate_fact_id)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, subject, content, proposed_scopes, target_fact_id, status, dedupe_verdict, dedupe_candidate_fact_id, created_at`,
		subject, content, scopes, targetFactID, verdictStr, candidate,
	).Scan(&d.ID, &d.Subject, &d.Content, &d.ProposedScopes, &d.TargetFactID, &statusStr, &scannedVerdict, &d.DedupeCandidateFactID, &d.CreatedAt)
	if err != nil {
		return StagedDiff{}, fmt.Errorf("store: insert staged diff: %w", err)
	}
	d.Status = DiffStatus(statusStr)
	if scannedVerdict != nil {
		dv := DedupeVerdict(*scannedVerdict)
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
	var visible bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (
		    SELECT 1 FROM facts f
		    WHERE f.id = $1
		      AND f.invalid_at IS NULL
		      AND EXISTS (SELECT 1 FROM fact_scopes fs WHERE fs.fact_id = f.id)
		      AND NOT EXISTS (
		          SELECT 1 FROM fact_scopes fs
		          WHERE fs.fact_id = f.id
		            AND NOT (fs.scope = ANY($2) OR fs.scope LIKE ANY($3))
		      )
		 )`,
		id, grantedScopes, prefixes,
	).Scan(&visible)
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

	var candidateID, candidateContent string
	var distance float64
	err = s.pool.QueryRow(ctx,
		`SELECT f.id, f.content, f.embedding <=> $1::vector AS distance
		 FROM facts f
		 WHERE f.invalid_at IS NULL AND f.embedding IS NOT NULL
		   AND EXISTS (SELECT 1 FROM fact_scopes fs WHERE fs.fact_id = f.id)
		   AND NOT EXISTS (
		       SELECT 1 FROM fact_scopes fs
		       WHERE fs.fact_id = f.id
		         AND NOT (fs.scope = ANY($2) OR fs.scope LIKE ANY($3))
		   )
		 ORDER BY f.embedding <=> $1::vector
		 LIMIT 1`,
		embParam, grantedScopes, prefixes,
	).Scan(&candidateID, &candidateContent, &distance)
	if errors.Is(err, pgx.ErrNoRows) {
		return DedupeNovel, "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("store: dedupe candidate search: %w", err)
	}

	switch {
	case candidateContent == content:
		return DedupeDuplicate, candidateID, nil
	case distance < dedupeCosineThreshold:
		return DedupeContradiction, candidateID, nil
	default:
		return DedupeNovel, "", nil
	}
}

// GetStagedDiff fetches a single diff by ID. Used by the approval UI's REST API to
// re-embed a diff's content at approval time — see CommitDiff's doc comment on why
// the embedding isn't persisted on the diff row itself.
func (s *Store) GetStagedDiff(ctx context.Context, id string) (StagedDiff, error) {
	var d StagedDiff
	var statusStr string
	var verdictStr *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, subject, content, proposed_scopes, target_fact_id, status,
		        dedupe_verdict, dedupe_candidate_fact_id, created_at, decided_at, decided_by
		 FROM staged_diffs WHERE id = $1`,
		id,
	).Scan(&d.ID, &d.Subject, &d.Content, &d.ProposedScopes, &d.TargetFactID,
		&statusStr, &verdictStr, &d.DedupeCandidateFactID, &d.CreatedAt, &d.DecidedAt, &d.DecidedBy)
	if err != nil {
		return StagedDiff{}, fmt.Errorf("store: get staged diff %s: %w", id, err)
	}
	d.Status = DiffStatus(statusStr)
	if verdictStr != nil {
		dv := DedupeVerdict(*verdictStr)
		d.DedupeVerdict = &dv
	}
	return d, nil
}

// ListStagedDiffs returns diffs in the given status, oldest first (review queue
// order) — used by the approval UI's REST API.
func (s *Store) ListStagedDiffs(ctx context.Context, status DiffStatus) ([]StagedDiff, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, subject, content, proposed_scopes, target_fact_id, status,
		        dedupe_verdict, dedupe_candidate_fact_id, created_at, decided_at, decided_by
		 FROM staged_diffs WHERE status = $1 ORDER BY created_at ASC`,
		string(status),
	)
	if err != nil {
		return nil, fmt.Errorf("store: list staged diffs: %w", err)
	}
	defer rows.Close()

	var diffs []StagedDiff
	for rows.Next() {
		var d StagedDiff
		var statusStr string
		var verdictStr *string
		if err := rows.Scan(&d.ID, &d.Subject, &d.Content, &d.ProposedScopes, &d.TargetFactID,
			&statusStr, &verdictStr, &d.DedupeCandidateFactID, &d.CreatedAt, &d.DecidedAt, &d.DecidedBy); err != nil {
			return nil, fmt.Errorf("store: scan staged diff: %w", err)
		}
		d.Status = DiffStatus(statusStr)
		if verdictStr != nil {
			dv := DedupeVerdict(*verdictStr)
			d.DedupeVerdict = &dv
		}
		diffs = append(diffs, d)
	}
	return diffs, rows.Err()
}

// RejectDiff marks a pending diff rejected. Never touches `facts`. decidedBy is
// logged to audit_log atomically with the rejection.
func (s *Store) RejectDiff(ctx context.Context, diffID, decidedBy string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if already committed

	tag, err := tx.Exec(ctx,
		`UPDATE staged_diffs SET status = 'rejected', decided_at = now(), decided_by = $2
		 WHERE id = $1 AND status = 'pending'`,
		diffID, decidedBy,
	)
	if err != nil {
		return fmt.Errorf("store: reject diff: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: diff %s is not pending", diffID)
	}

	if err := logAudit(ctx, tx, "diff_rejected", decidedBy, nil, nil, &diffID, nil); err != nil {
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

	var content string
	var scopes []string
	var targetFactID *string
	var status string
	err = tx.QueryRow(ctx,
		`SELECT content, proposed_scopes, target_fact_id, status
		 FROM staged_diffs WHERE id = $1 FOR UPDATE`,
		diffID,
	).Scan(&content, &scopes, &targetFactID, &status)
	if err != nil {
		return Fact{}, fmt.Errorf("store: load staged diff %s: %w", diffID, err)
	}
	if status != string(DiffPending) {
		return Fact{}, fmt.Errorf("store: diff %s is not pending (status=%s)", diffID, status)
	}

	// The dedupe verdict was computed once, at ProposeDiff time. Two identical
	// proposals can both be staged as "novel" (neither sees the other, since
	// neither has committed yet) and later both reach CommitDiff — re-checking
	// only at staging time would let both become real, duplicate facts. Re-run
	// the exact-content check here, inside this transaction, right before
	// inserting. This narrows the race to genuinely concurrent commits (the
	// window between this SELECT and the INSERT below) rather than closing it
	// completely — full closure would need a database-level uniqueness
	// constraint, which doesn't compose cleanly with the supersession CHECK
	// constraint below without real complexity (a partial unique index can't be
	// deferrable, so the target-invalidation and new-fact-insert ordering would
	// need to change too). Flagged as a follow-up, not done here: this is a
	// large jump in complexity for a race that's already far narrower than the
	// original bug (no re-check at all).
	targetExclude := targetFactID
	var dupExists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (
		    SELECT 1 FROM facts
		    WHERE invalid_at IS NULL AND content = $1
		      AND ($2::uuid IS NULL OR id != $2)
		 )`,
		content, targetExclude,
	).Scan(&dupExists); err != nil {
		return Fact{}, fmt.Errorf("store: duplicate content check: %w", err)
	}
	if dupExists {
		return Fact{}, fmt.Errorf("store: an active fact with identical content already exists; re-review before committing diff %s", diffID)
	}

	embParam, err := toVectorParam(embedding)
	if err != nil {
		return Fact{}, err
	}

	var f Fact
	err = tx.QueryRow(ctx,
		`INSERT INTO facts (content, embedding, source_staged_diff_id)
		 VALUES ($1, $2, $3)
		 RETURNING id, content, created_at, valid_at`,
		content, embParam, diffID,
	).Scan(&f.ID, &f.Content, &f.CreatedAt, &f.ValidAt)
	if err != nil {
		return Fact{}, fmt.Errorf("store: insert committed fact: %w", err)
	}

	for _, sc := range scopes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO fact_scopes (fact_id, scope) VALUES ($1, $2)`,
			f.ID, sc,
		); err != nil {
			return Fact{}, fmt.Errorf("store: insert fact scope %q: %w", sc, err)
		}
	}
	f.Scopes = scopes

	if targetFactID != nil {
		// Lock the target fact row before checking/setting its supersession state.
		// Without this, two diffs racing to commit against the same target fact
		// could both pass an unlocked "WHERE invalid_at IS NULL" check, both
		// UPDATE, and both get marked committed — silently losing one
		// supersession link with no error raised (exactly the kind of silent
		// partial failure AGENTS.md §6 forbids in the write/audit path). FOR
		// UPDATE serializes the two transactions: the second one blocks here
		// until the first commits, then re-reads the now-current invalid_at and
		// correctly detects the conflict instead of racing past it.
		var targetInvalidAt *time.Time
		err := tx.QueryRow(ctx,
			`SELECT invalid_at FROM facts WHERE id = $1 FOR UPDATE`,
			*targetFactID,
		).Scan(&targetInvalidAt)
		if err != nil {
			return Fact{}, fmt.Errorf("store: lock target fact %s: %w", *targetFactID, err)
		}
		if targetInvalidAt != nil {
			return Fact{}, fmt.Errorf("store: target fact %s was already superseded by another diff", *targetFactID)
		}

		if _, err := tx.Exec(ctx,
			`UPDATE facts SET invalid_at = $2, expired_at = now(), superseded_by = $3 WHERE id = $1`,
			*targetFactID, f.ValidAt, f.ID,
		); err != nil {
			return Fact{}, fmt.Errorf("store: supersede target fact %s: %w", *targetFactID, err)
		}
	}

	if _, err := tx.Exec(ctx,
		`UPDATE staged_diffs SET status = 'committed', decided_at = now(), decided_by = $2 WHERE id = $1`,
		diffID, decidedBy,
	); err != nil {
		return Fact{}, fmt.Errorf("store: mark diff committed: %w", err)
	}

	if err := logAudit(ctx, tx, "diff_committed", decidedBy, &f.ID, nil, &diffID, scopes); err != nil {
		return Fact{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Fact{}, fmt.Errorf("store: commit staged diff %s: %w", diffID, err)
	}
	return f, nil
}
