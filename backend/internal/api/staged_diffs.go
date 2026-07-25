package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/abradner/chuvar/backend/internal/store"
)

type stagedDiffView struct {
	ID                    string   `json:"id"`
	Subject               string   `json:"subject"`
	Content               string   `json:"content"`
	ProposedScopes        []string `json:"proposed_scopes"`
	TargetFactID          *string  `json:"target_fact_id,omitempty"`
	Status                string   `json:"status"`
	DedupeVerdict         *string  `json:"dedupe_verdict,omitempty"`
	DedupeCandidateFactID *string  `json:"dedupe_candidate_fact_id,omitempty"`
	CreatedAt             string   `json:"created_at"`
}

func toStagedDiffView(d store.StagedDiff) stagedDiffView {
	v := stagedDiffView{
		ID:                    d.ID,
		Subject:               d.Subject,
		Content:               d.Content,
		ProposedScopes:        d.ProposedScopes,
		TargetFactID:          d.TargetFactID,
		Status:                string(d.Status),
		DedupeCandidateFactID: d.DedupeCandidateFactID,
		CreatedAt:             d.CreatedAt.Format(timeFormat),
	}
	if d.DedupeVerdict != nil {
		s := string(*d.DedupeVerdict)
		v.DedupeVerdict = &s
	}
	return v
}

const timeFormat = "2006-01-02T15:04:05Z07:00"

// listStagedDiffs handles GET /api/staged-diffs?status=pending (default: pending).
func (a *API) listStagedDiffs(w http.ResponseWriter, r *http.Request) {
	status := store.DiffStatus(r.URL.Query().Get("status"))
	if status == "" {
		status = store.DiffPending
	}

	diffs, err := a.Store.ListStagedDiffs(r.Context(), status)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "listStagedDiffs", "could not list staged diffs", err)
		return
	}

	views := make([]stagedDiffView, len(diffs))
	for i, d := range diffs {
		views[i] = toStagedDiffView(d)
	}
	writeJSON(w, http.StatusOK, views)
}

type decisionRequest struct {
	DecidedBy string `json:"decided_by"`
}

// decidedBy extracts who's approving/rejecting a diff. This gets written straight
// into the permanent decided_by column on the audit trail, so a malformed or
// missing value is a 400, not a silently fabricated "unknown-reviewer" identity —
// AGENTS.md §6 is explicit that the consent/audit path must not swallow errors
// silently, and laundering a bad request into a fake-but-plausible-looking audit
// identity is exactly that.
func decidedBy(r *http.Request) (string, error) {
	var req decisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "", fmt.Errorf("decoding request body: %w", err)
	}
	if req.DecidedBy == "" {
		return "", errors.New("decided_by is required")
	}
	return req.DecidedBy, nil
}

// approveStagedDiff handles POST /api/staged-diffs/{id}/approve. This is the only
// path in the whole system, outside the store package's own tests, that turns a
// staged diff into a real fact — see AGENTS.md §3.1. Gated by requireAuth (see the
// package comment) same as every other route here.
func (a *API) approveStagedDiff(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	reviewer, err := decidedBy(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	diff, err := a.Store.GetStagedDiff(r.Context(), id)
	if err != nil {
		// GetStagedDiff wraps every failure the same way, including a real DB
		// error, not just "no row with that id" — turning that straight into a
		// 404 with nothing logged made a genuine internal failure indistinguishable
		// from a bad ID at both the client and in the logs. Log it server-side; the
		// client still gets 404 either way for now (disambiguating via
		// errors.Is(err, pgx.ErrNoRows) is a fine follow-up, not required to fix
		// the "silently masked" part of this).
		slog.Error("api: approveStagedDiff: get staged diff", "id", id, "error", err)
		writeError(w, http.StatusNotFound, errors.New("staged diff not found"))
		return
	}

	vec, err := a.Embedder.Embed(r.Context(), diff.Content)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "approveStagedDiff.Embed", "could not embed diff content", err)
		return
	}

	fact, err := a.Store.CommitDiff(r.Context(), id, reviewer, vec)
	if err != nil {
		writeStoreError(w, http.StatusConflict, "approveStagedDiff.CommitDiff", "could not approve diff — it may no longer be pending", err)
		return
	}
	writeJSON(w, http.StatusOK, fact)
}

// rejectStagedDiff handles POST /api/staged-diffs/{id}/reject.
func (a *API) rejectStagedDiff(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	reviewer, err := decidedBy(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if err := a.Store.RejectDiff(r.Context(), id, reviewer); err != nil {
		writeStoreError(w, http.StatusConflict, "rejectStagedDiff", "could not reject diff — it may no longer be pending", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
