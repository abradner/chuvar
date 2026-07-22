package store

import (
	"errors"
	"fmt"

	"context"

	"github.com/jackc/pgx/v5"
	"github.com/pgvector/pgvector-go"
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
func (s *Store) ProposeDiff(ctx context.Context, subject, content string, scopes []string, embedding []float32, targetFactID *string) (StagedDiff, error) {
	if content == "" {
		return StagedDiff{}, fmt.Errorf("store: diff content must not be empty")
	}
	if len(scopes) == 0 {
		return StagedDiff{}, fmt.Errorf("store: diff must include at least one scope")
	}

	verdict, candidateID, err := s.findDedupeCandidate(ctx, content, embedding)
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

// findDedupeCandidate looks for the nearest active fact by cosine distance. An
// empty embedding (caller has no Embedder configured) skips the check entirely and
// reports novel — that's a degraded mode, not a silent failure, since the caller
// chose not to provide one.
func (s *Store) findDedupeCandidate(ctx context.Context, content string, embedding []float32) (DedupeVerdict, string, error) {
	if len(embedding) == 0 {
		return DedupeNovel, "", nil
	}

	var candidateID, candidateContent string
	var distance float64
	err := s.pool.QueryRow(ctx,
		`SELECT id, content, embedding <=> $1 AS distance
		 FROM facts
		 WHERE invalid_at IS NULL AND embedding IS NOT NULL
		 ORDER BY embedding <=> $1
		 LIMIT 1`,
		pgvector.NewVector(embedding),
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

// RejectDiff marks a pending diff rejected. Never touches `facts`.
func (s *Store) RejectDiff(ctx context.Context, diffID, decidedBy string) error {
	tag, err := s.pool.Exec(ctx,
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

	var f Fact
	err = tx.QueryRow(ctx,
		`INSERT INTO facts (content, embedding, source_staged_diff_id)
		 VALUES ($1, $2, $3)
		 RETURNING id, content, created_at, valid_at`,
		content, pgvector.NewVector(embedding), diffID,
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
		if _, err := tx.Exec(ctx,
			`UPDATE facts SET invalid_at = $2, expired_at = now(), superseded_by = $3
			 WHERE id = $1 AND invalid_at IS NULL`,
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

	if err := tx.Commit(ctx); err != nil {
		return Fact{}, fmt.Errorf("store: commit staged diff %s: %w", diffID, err)
	}
	return f, nil
}
