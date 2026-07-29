package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/abradner/chuvar/backend/internal/scope"
	"github.com/abradner/chuvar/backend/internal/store"
)

// maxScopesPerGrant bounds how many scopes a single request can create a grant
// for. Nothing about a real grant needs anywhere near this many — it exists so a
// malformed or hostile request can't turn a single POST into thousands of
// individual grant_scopes inserts inside one transaction.
const maxScopesPerGrant = 50

// maxGrantTTLSeconds bounds how far out a grant's expiry can be requested.
// Arbitrary-but-generous (a year), not a product decision — it exists so a client
// sending a pathological ttl_seconds (near math.MaxInt64) can't overflow the
// *time.Second conversion below or hand store.CreateGrant a duration that produces
// a nonsensical expires_at via time.Now().Add.
const maxGrantTTLSeconds = 365 * 24 * 3600

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
		writeStoreError(w, http.StatusInternalServerError, "listGrants", "could not list grants", err)
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
// approved_by is the authenticated reviewer (reviewerFromContext), not a request
// body field — see the package comment.
func (a *API) createGrant(w http.ResponseWriter, r *http.Request) {
	approvedBy := reviewerFromContext(r.Context()).Label

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
	if !store.ValidDepth(req.Depth) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("depth must be one of summary, facts, full (got %q)", req.Depth))
		return
	}
	if len(req.Scopes) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("scopes must not be empty"))
		return
	}
	if len(req.Scopes) > maxScopesPerGrant {
		writeError(w, http.StatusBadRequest, fmt.Errorf("scopes exceeds max of %d", maxScopesPerGrant))
		return
	}
	scopes := make([]scope.Scope, len(req.Scopes))
	for i, s := range req.Scopes {
		if err := scope.Validate(scope.Scope(s)); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		scopes[i] = scope.Scope(s)
	}
	// grant_scopes has PRIMARY KEY (grant_id, scope) — without this check, a
	// duplicate scope in the request reaches the store as a constraint violation
	// (a 500) instead of a clean 400 naming the actual problem.
	if deduped := scope.Dedupe(scopes); len(deduped) != len(scopes) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("scopes must not contain duplicates"))
		return
	}
	if req.TTLSeconds != nil && *req.TTLSeconds <= 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("ttl_seconds must be positive if provided (got %d)", *req.TTLSeconds))
		return
	}
	if req.TTLSeconds != nil && *req.TTLSeconds > maxGrantTTLSeconds {
		writeError(w, http.StatusBadRequest, fmt.Errorf("ttl_seconds exceeds max of %d (got %d)", maxGrantTTLSeconds, *req.TTLSeconds))
		return
	}

	var ttl *time.Duration
	if req.TTLSeconds != nil {
		d := time.Duration(*req.TTLSeconds) * time.Second
		ttl = &d
	}

	// kind is hardcoded to memory here — this endpoint doesn't expose a way to
	// create a capability-kind grant yet (that's the Agent Capability Broker
	// workstream's own surface to design, not guessed at in this batch).
	g, err := a.Store.CreateGrant(r.Context(), req.Subject, req.Scopes, string(store.GrantKindMemory), req.Depth, ttl, approvedBy)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "createGrant", "could not create grant", err)
		return
	}
	writeJSON(w, http.StatusCreated, toGrantView(g))
}

// revokeGrant handles POST /api/grants/{id}/revoke. revoked_by is the
// authenticated reviewer (reviewerFromContext), not a request body field.
func (a *API) revokeGrant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	revokedBy := reviewerFromContext(r.Context()).Label
	if err := a.Store.RevokeGrant(r.Context(), id, revokedBy); err != nil {
		writeStoreError(w, http.StatusConflict, "revokeGrant", "could not revoke grant — it may not exist or already be revoked", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
