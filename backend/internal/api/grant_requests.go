package api

import (
	"fmt"
	"net/http"

	"github.com/abradner/chuvar/backend/internal/store"
)

// validGrantRequestStatuses mirrors the CHECK constraint on grant_requests.status
// — same hand-synced closed-vocabulary stance as validStatuses in staged_diffs.go.
var validGrantRequestStatuses = map[store.GrantRequestStatus]bool{
	store.GrantRequestPending:  true,
	store.GrantRequestApproved: true,
	store.GrantRequestDenied:   true,
}

type grantRequestView struct {
	ID                  string   `json:"id"`
	Subject             string   `json:"subject"`
	RequestedScopes     []string `json:"requested_scopes"`
	Depth               string   `json:"depth"`
	RequestedTTLSeconds *int     `json:"requested_ttl_seconds,omitempty"`
	Justification       string   `json:"justification"`
	Status              string   `json:"status"`
	CreatedAt           string   `json:"created_at"`
	DecidedAt           *string  `json:"decided_at,omitempty"`
	DecidedBy           *string  `json:"decided_by,omitempty"`
	ResultingGrantID    *string  `json:"resulting_grant_id,omitempty"`
}

func toGrantRequestView(r store.GrantRequest) grantRequestView {
	v := grantRequestView{
		ID:                  r.ID,
		Subject:             r.Subject,
		RequestedScopes:     r.RequestedScopes,
		Depth:               r.Depth,
		RequestedTTLSeconds: r.RequestedTTLSeconds,
		Justification:       r.Justification,
		Status:              string(r.Status),
		CreatedAt:           r.CreatedAt.Format(timeFormat),
		ResultingGrantID:    r.ResultingGrantID,
	}
	if r.DecidedAt != nil {
		s := r.DecidedAt.Format(timeFormat)
		v.DecidedAt = &s
	}
	if r.DecidedBy != nil {
		v.DecidedBy = r.DecidedBy
	}
	return v
}

// listGrantRequests handles GET /api/grant-requests?status=pending (default: pending).
func (a *API) listGrantRequests(w http.ResponseWriter, r *http.Request) {
	status := store.GrantRequestStatus(r.URL.Query().Get("status"))
	if status == "" {
		status = store.GrantRequestPending
	}
	if !validGrantRequestStatuses[status] {
		writeError(w, http.StatusBadRequest, fmt.Errorf("status must be one of pending, approved, denied (got %q)", status))
		return
	}

	reqs, err := a.Store.ListGrantRequests(r.Context(), status)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "listGrantRequests", "could not list grant requests", err)
		return
	}
	views := make([]grantRequestView, len(reqs))
	for i, req := range reqs {
		views[i] = toGrantRequestView(req)
	}
	writeJSON(w, http.StatusOK, views)
}

// approveGrantRequest handles POST /api/grant-requests/{id}/approve. This is the
// only REST path, alongside createGrant, that ever creates a real grant — see
// store.ApproveGrantRequest's doc comment. approved_by is the authenticated
// reviewer.
func (a *API) approveGrantRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	approvedBy := reviewerFromContext(r.Context())

	g, err := a.Store.ApproveGrantRequest(r.Context(), id, approvedBy)
	if err != nil {
		writeStoreError(w, http.StatusConflict, "approveGrantRequest", "could not approve grant request — it may no longer be pending", err)
		return
	}
	writeJSON(w, http.StatusOK, toGrantView(g))
}

// denyGrantRequest handles POST /api/grant-requests/{id}/deny.
func (a *API) denyGrantRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	deniedBy := reviewerFromContext(r.Context())

	if err := a.Store.DenyGrantRequest(r.Context(), id, deniedBy); err != nil {
		writeStoreError(w, http.StatusConflict, "denyGrantRequest", "could not deny grant request — it may no longer be pending", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
