package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"memoryvault/internal/scope"
	"memoryvault/internal/store"
)

type grantView struct {
	ID        string   `json:"id"`
	Subject   string   `json:"subject"`
	Scopes    []string `json:"scopes"`
	Depth     string   `json:"depth"`
	Active    bool     `json:"active"`
	CreatedAt string   `json:"created_at"`
	ExpiresAt *string  `json:"expires_at,omitempty"`
	RevokedAt *string  `json:"revoked_at,omitempty"`
}

func toGrantView(g store.Grant) grantView {
	now := time.Now()
	v := grantView{
		ID:        g.ID,
		Subject:   g.Subject,
		Scopes:    g.Scopes,
		Depth:     g.Depth,
		Active:    g.Active(now),
		CreatedAt: g.CreatedAt.Format(timeFormat),
	}
	if g.ExpiresAt != nil {
		s := g.ExpiresAt.Format(timeFormat)
		v.ExpiresAt = &s
	}
	if g.RevokedAt != nil {
		s := g.RevokedAt.Format(timeFormat)
		v.RevokedAt = &s
	}
	return v
}

// listGrants handles GET /api/grants?subject=X.
func (a *API) listGrants(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")
	if subject == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("subject query parameter is required"))
		return
	}

	grants, err := a.Store.ListGrants(r.Context(), subject)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	views := make([]grantView, len(grants))
	for i, g := range grants {
		views[i] = toGrantView(g)
	}
	writeJSON(w, http.StatusOK, views)
}

type createGrantRequest struct {
	Subject    string   `json:"subject"`
	Scopes     []string `json:"scopes"`
	Depth      string   `json:"depth"`
	TTLSeconds *int     `json:"ttl_seconds,omitempty"`
}

// createGrant handles POST /api/grants. This is the human-approval side of the
// consent model: a grant only ever gets created through this endpoint (or directly
// in the store, e.g. in tests) — never as a side effect of an agent's own request.
func (a *API) createGrant(w http.ResponseWriter, r *http.Request) {
	var req createGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
		return
	}
	if req.Subject == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("subject is required"))
		return
	}
	if req.Depth == "" {
		req.Depth = "facts"
	}
	for _, s := range req.Scopes {
		if err := scope.Validate(scope.Scope(s)); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	var ttl *time.Duration
	if req.TTLSeconds != nil {
		d := time.Duration(*req.TTLSeconds) * time.Second
		ttl = &d
	}

	g, err := a.Store.CreateGrant(r.Context(), req.Subject, req.Scopes, req.Depth, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, toGrantView(g))
}

// revokeGrant handles POST /api/grants/{id}/revoke.
func (a *API) revokeGrant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.Store.RevokeGrant(r.Context(), id); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
