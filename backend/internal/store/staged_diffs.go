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
// proposerGranted is the proposing subject's current granted (scope, depth) pairs
// — used three ways:
//   - The dedupe candidate search only considers facts covered by these scopes,
//     at ANY depth (see findDedupeCandidate). Without this, an ungranted agent
//     could propose guessed sensitive content and distinguish "duplicate"/
//     "contradiction" from "novel" via the returned verdict, then reuse the
//     leaked candidate fact ID as targetFactID — a confidentiality leak through a
//     side channel that isn't the read path at all. Found in review.
//   - If targetFactID is set, it must be covered by these scopes too: a proposer
//     can only target a fact they can already read. Without this, an agent could
//     supply an arbitrary fact UUID (guessed, brute-forced, or leaked exactly as
//     above) as a supersession target, and — since the approval UI now surfaces
//     the target's current content (internal/api's getFact / the frontend) — a
//     human reviewer would at least see the replacement, but this check stops the
//     proposal from ever being staged in the first place. Also found in review.
//   - The dedupe verdict/candidate ID returned to the CALLER (as opposed to what
//     gets persisted to the staged_diffs row) is redacted by depth — see
//     discloseDedupeResult below and findDedupeCandidate's doc comment for the
//     full threat model (GitHub issue #83).
func (s *Store) ProposeDiff(ctx context.Context, subject, content string, scopes []string, embedding []float32, targetFactID *string, proposerGranted []GrantedScope) (StagedDiff, error) {
	if content == "" {
		return StagedDiff{}, fmt.Errorf("store: diff content must not be empty")
	}
	if len(scopes) == 0 {
		return StagedDiff{}, fmt.Errorf("store: diff must include at least one scope")
	}
	// A fact is always a memory-kind object, so its scopes must be untargeted
	// (see scope.ValidateMemory): the fact-visibility LIKE queries below and in
	// SearchFacts match scopes target-blind, so a targeted fact scope would be
	// readable across targets. Reject at propose time for a clean early error;
	// ApproveStagedDiff/CommitDiff re-checks at the actual fact-creation
	// chokepoint so a staged_diffs row inserted some other way (psql, fixture)
	// can't smuggle a targeted scope onto a live fact. Found in review of #99.
	if err := validateMemoryFactScopes(scopes); err != nil {
		return StagedDiff{}, err
	}

	grantedScopes := grantedScopeStrings(proposerGranted)

	if targetFactID != nil {
		visible, err := s.factVisibleToScopes(ctx, *targetFactID, grantedScopes)
		if err != nil {
			return StagedDiff{}, err
		}
		if !visible {
			return StagedDiff{}, fmt.Errorf("store: target_fact_id %s is not covered by the proposer's granted scopes", *targetFactID)
		}
	}

	// verdict/candidateID are the ACCURATE result of the comparison — computed
	// against every fact the proposer's scopes cover, at any depth, on purpose:
	// see findDedupeCandidate's doc comment for why narrowing the comparison
	// itself would silently let real duplicates through. This accurate pair is
	// what gets persisted below, unconditionally, so a human reviewer (via the
	// approval UI / GetStagedDiff) always sees exactly what matched.
	verdict, candidateID, candidateDepth, err := s.findDedupeCandidate(ctx, content, embedding, grantedScopes, proposerGranted)
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

	// disclosedVerdict/disclosedCandidate are what the PROPOSER actually learns
	// — mcptools/propose_write.go copies this returned struct's fields verbatim
	// into the MCP tool response, so this is the one place that decides what
	// reaches the caller. Deliberately computed from the just-persisted
	// accurate values, not used to overwrite them: the DB row above already has
	// the real verdict/ID regardless of what's disclosed here. See
	// discloseDedupeResult's doc comment for the reasoning (GitHub issue #83).
	disclosedVerdict, disclosedCandidate := discloseDedupeResult(verdict, candidateID, candidateDepth)

	// Only ID/Status/CreatedAt come back from the database; the rest is what we
	// just sent. Reconstructing rather than echoing is what lets the agent role
	// hold column-level SELECT on three generated columns instead of a
	// table-wide read over every subject's proposed content.
	d := StagedDiff{
		ID:                    row.ID,
		Subject:               subject,
		Content:               content,
		ProposedScopes:        scopes,
		TargetFactID:          targetFactID,
		Status:                DiffStatus(row.Status),
		DedupeCandidateFactID: disclosedCandidate,
		CreatedAt:             row.CreatedAt,
		DedupeVerdict:         &disclosedVerdict,
	}
	return d, nil
}

// grantedScopeStrings discards the depth half of each pair and dedupes — the
// scope-only checks below (factVisibleToScopes, findDedupeCandidate's WHERE
// clause) need only "is this scope covered," not at what depth; depth is
// applied afterward, once, in discloseDedupeResult. Mirrors mcptools'
// grantedScopeStrs (internal/mcptools/read_with_scope_check.go) — not shared
// directly since that helper lives in a package store must not import.
func grantedScopeStrings(granted []GrantedScope) []string {
	seen := make(map[string]struct{}, len(granted))
	out := make([]string, 0, len(granted))
	for _, g := range granted {
		if _, ok := seen[g.Scope]; ok {
			continue
		}
		seen[g.Scope] = struct{}{}
		out = append(out, g.Scope)
	}
	return out
}

// discloseDedupeResult decides what a propose_write caller actually learns
// from a dedupe match — separate from what ProposeDiff already persisted to
// staged_diffs (the accurate verdict/candidateID, for human review) above.
// candidateDepth is the effective depth (facts.go's effectiveDepth) the
// matched candidate fact would be disclosed at if the proposer read it
// through the normal search path; "" when there was no candidate at all
// (verdict == DedupeNovel).
//
// At "facts" or "full" depth, the proposer could already read the candidate's
// exact content directly — SearchFacts (facts.go) redacts to Summary only at
// "summary" depth — so echoing the real verdict/ID discloses nothing beyond
// what a legitimate search already would. Unchanged from pre-fix behavior.
//
// At "summary" depth (or no candidate — nothing to compute a depth for),
// content is NOT otherwise readable. A "duplicate" verdict there is exactly
// the confirm-by-guessing oracle GitHub issue #83 describes: the proposer
// supplied the guess, an exact-content match confirms it verbatim, and the
// verdict alone is enough for a low-entropy fact ("blood type is O+") to be a
// real leak. "contradiction" is a weaker signal (embedding-close, not exact)
// but distinguishing it from "duplicate" is itself the leak — it tells the
// caller their guess was closer than average, several guesses that flag
// "contradiction" narrow the search — so both collapse to the same
// DedupeNeedsReview signal, and the candidate ID is withheld either way,
// closing the supersession-target leak (findDedupeCandidate's doc comment)
// from the same disclosure.
//
// "novel" is left alone regardless of depth: reporting "no close match" is
// required for dedupe to remain useful at all — the correctness property this
// fix must not trade away, see ProposeDiff's doc comment — and unlike
// duplicate/contradiction it does not confirm exact content, only that
// nothing embedding-close exists among facts the proposer's scopes cover.
// This is a deliberate, accepted residual: an adversary who never gets a
// non-novel response at all still learns nothing; one who does still can't
// tell duplicate from contradiction, so cannot confirm an exact guess. What
// it does NOT close: a floor of "there exists something embedding-adjacent to
// my guess" is inherent to dedupe working across depths at all, and no
// verdict-shaping can remove it without breaking the correctness guarantee.
func discloseDedupeResult(verdict DedupeVerdict, candidateID, candidateDepth string) (DedupeVerdict, *string) {
	if verdict == DedupeNovel || candidateDepth != "summary" {
		if candidateID == "" {
			return verdict, nil
		}
		id := candidateID
		return verdict, &id
	}
	return DedupeNeedsReview, nil
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
//
// grantedScopes gates the candidate SEARCH itself (scope-filtered, at ANY depth —
// unchanged from before this fix, and deliberately so: dedupe must still catch a
// genuine duplicate against a fact the proposer can only read at summary depth,
// see ProposeDiff's doc comment on why narrowing this would silently degrade
// correctness). proposerGranted (the same set, with depth) is used only for the
// fourth return value, candidateDepth — the effective depth (facts.go's
// effectiveDepth) the matched candidate would be disclosed at through the normal
// read path. The verdict and candidate ID returned here are always the accurate
// ones; candidateDepth is what lets the caller (ProposeDiff, via
// discloseDedupeResult) decide how much of that accuracy the proposer gets to see.
//
// Was previously scope-filtered but NOT depth-filtered at all, unlike SearchFacts
// (facts.go): a caller holding only a summary-depth grant got a full-fidelity
// "duplicate" verdict plus the matching fact's ID when it guessed that fact's
// exact content — a guess-and-confirm oracle over content SearchFacts would have
// redacted to a summary. Verified reproducible before this fix: exact guess
// returned duplicate + candidate ID, wrong guess returned novel. GitHub issue #83;
// see discloseDedupeResult for the fix and its residual (the "novel" signal itself
// is not, and cannot be, suppressed without breaking correctness).
func (s *Store) findDedupeCandidate(ctx context.Context, content string, embedding []float32, grantedScopes []string, proposerGranted []GrantedScope) (DedupeVerdict, string, string, error) {
	if len(embedding) == 0 || len(grantedScopes) == 0 {
		return DedupeNovel, "", "", nil
	}

	embParam, err := toVectorParam(embedding)
	if err != nil {
		return "", "", "", err
	}
	prefixes := scopePrefixes(grantedScopes)

	row, err := s.q.FindDedupeCandidate(ctx, sqlcgen.FindDedupeCandidateParams{
		Embedding1:    *embParam,
		GrantedScopes: grantedScopes,
		ScopePrefixes: prefixes,
		Embedding2:    *embParam,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DedupeNovel, "", "", nil
	}
	if err != nil {
		return "", "", "", fmt.Errorf("store: dedupe candidate search: %w", err)
	}

	var verdict DedupeVerdict
	switch {
	case row.Content == content:
		verdict = DedupeDuplicate
	case row.Distance.Float64 < dedupeCosineThreshold:
		verdict = DedupeContradiction
	default:
		return DedupeNovel, "", "", nil
	}

	// effectiveDepth (facts.go) is the same function SearchFacts uses to decide
	// Content-vs-Summary for a read result — reused here rather than
	// reimplemented so the two disclosure surfaces can't drift out of sync with
	// each other. row.Scopes came back NULL-safe as a non-nil (possibly empty)
	// array from the array_agg subselect; an empty result is unreachable given
	// the query's own EXISTS guard (queries/staged_diffs.sql), but effectiveDepth
	// already fails closed to "summary" on an empty factScopes input regardless.
	depth, err := effectiveDepth(row.Scopes, proposerGranted)
	if err != nil {
		return "", "", "", fmt.Errorf("store: dedupe candidate depth: %w", err)
	}

	return verdict, row.ID, depth, nil
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

// ListStagedDiffsPage returns up to limit diffs in status, oldest first
// (review-queue order — matches the pre-pagination ORDER BY), starting
// strictly after cursor. cursor nil means "first page." The bool return
// reports whether at least one further row exists past the page returned, so
// the caller (internal/api's listStagedDiffs) knows whether to hand back a
// next_cursor. See queries/staged_diffs.sql's ListStagedDiffsPage for the
// keyset-vs-offset rationale.
func (s *Store) ListStagedDiffsPage(ctx context.Context, status DiffStatus, limit int, cursor *ListCursor) ([]StagedDiff, bool, error) {
	if limit <= 0 {
		return nil, false, fmt.Errorf("store: limit must be positive")
	}
	params := sqlcgen.ListStagedDiffsPageParams{
		Status: string(status),
		// Requesting limit+1, not limit, is what lets hasMore below be
		// answered from this one query instead of a second COUNT.
		Lim: int64(limit) + 1,
	}
	if cursor != nil {
		createdAt := cursor.CreatedAt
		id := cursor.ID
		params.CursorCreatedAt = &createdAt
		params.CursorID = &id
	}
	rows, err := s.q.ListStagedDiffsPage(ctx, params)
	if err != nil {
		return nil, false, fmt.Errorf("store: list staged diffs page: %w", err)
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	diffs := make([]StagedDiff, len(rows))
	for i, r := range rows {
		diffs[i] = toStagedDiff(r)
	}
	return diffs, hasMore, nil
}

// ListStagedDiffsBounded returns up to limit diffs in status, oldest first,
// with no cursor/resumption support — the /api/events SSE poll loop
// (internal/api/events.go's streamEvents) calls this every eventPollInterval
// per connected client and needs a bounded snapshot of "currently pending,"
// not a page it walks forward across ticks. See the backing query's own doc
// comment (queries/staged_diffs.sql) for the full reasoning.
func (s *Store) ListStagedDiffsBounded(ctx context.Context, status DiffStatus, limit int) ([]StagedDiff, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("store: limit must be positive")
	}
	rows, err := s.q.ListStagedDiffsBounded(ctx, sqlcgen.ListStagedDiffsBoundedParams{
		Status: string(status),
		Lim:    int64(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("store: list staged diffs bounded: %w", err)
	}
	diffs := make([]StagedDiff, len(rows))
	for i, r := range rows {
		diffs[i] = toStagedDiff(r)
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

	if err := logAudit(ctx, qtx, "diff_rejected", decidedBy, nil, nil, &diffID, nil, nil, nil); err != nil {
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
//
// embedding and summary are both computed by the caller (api.approveStagedDiff)
// before this call, outside this transaction — real implementations of either are
// external/non-trivial-latency calls, and CommitDiff holds a row lock on the
// target fact (below) for its duration; making either call inside that lock's
// scope would turn an external call's latency into lock-hold time. summary of ""
// means "no summarizer configured or it returned nothing," stored as NULL, not as
// an empty-but-present summary — see facts.go's SearchFacts on why that
// distinction matters (fail closed to no-content, not empty-content, at summary
// depth).
func (s *Store) CommitDiff(ctx context.Context, diffID, decidedBy string, embedding []float32, summary string) (Fact, error) {
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

	var summaryParam *string
	if summary != "" {
		summaryParam = &summary
	}

	// The fact-creation chokepoint for the untargeted-memory-scope invariant
	// (see ProposeDiff and scope.ValidateMemory). ProposeDiff already rejects
	// targeted scopes, but this diff's proposed_scopes is plain TEXT[] with no
	// format CHECK, so a row that reached the table any other way (psql, a
	// fixture, a future import) must not be committable into a live fact
	// carrying a target the visibility SQL would match target-blind. Checked
	// before InsertFact so a bad diff writes nothing at all.
	if err := validateMemoryFactScopes(diff.ProposedScopes); err != nil {
		return Fact{}, err
	}

	factRow, err := qtx.InsertFact(ctx, sqlcgen.InsertFactParams{
		Content:            diff.Content,
		Summary:            summaryParam,
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

	if err := logAudit(ctx, qtx, "diff_committed", decidedBy, &f.ID, nil, &diffID, nil, diff.ProposedScopes, nil); err != nil {
		return Fact{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Fact{}, fmt.Errorf("store: commit staged diff %s: %w", diffID, err)
	}
	return f, nil
}
