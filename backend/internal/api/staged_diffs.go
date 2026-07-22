package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"memoryvault/internal/store"
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
		writeError(w, http.StatusInternalServerError, err)
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

func decidedByOrDefault(r *http.Request) string {
	var req decisionRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // best-effort; empty body is fine
	}
	if req.DecidedBy == "" {
		return "unknown-reviewer"
	}
	return req.DecidedBy
}

// approveStagedDiff handles POST /api/staged-diffs/{id}/approve. This is the only
// path in the whole system, outside the store package's own tests, that turns a
// staged diff into a real fact — see AGENTS.md §3.1.
func (a *API) approveStagedDiff(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	decidedBy := decidedByOrDefault(r)

	diff, err := a.Store.GetStagedDiff(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}

	vec, err := a.Embedder.Embed(r.Context(), diff.Content)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("embedding diff content: %w", err))
		return
	}

	fact, err := a.Store.CommitDiff(r.Context(), id, decidedBy, vec)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, fact)
}

// rejectStagedDiff handles POST /api/staged-diffs/{id}/reject.
func (a *API) rejectStagedDiff(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	decidedBy := decidedByOrDefault(r)

	if err := a.Store.RejectDiff(r.Context(), id, decidedBy); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
