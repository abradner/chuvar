package api

// GET /api/agent/grants and POST /api/agent/grant-requests are the HTTP
// twins of internal/mcptools/list_grants.go and request_grant.go — see
// agent_routes.go's package comment for why this is a deliberate, temporary
// duplicate.
import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/abradner/chuvar/backend/internal/scope"
	"github.com/abradner/chuvar/backend/internal/store"
)

// agentGrantView mirrors mcptools.grantView (list_grants.go) — the calling
// agent's own-grants shape. Deliberately distinct from grantView (grants.go),
// which is the reviewer-facing, ?subject=-parameterized, cursor-paginated
// shape: an agent token only ever sees its own subject's grants (bound at
// auth time, not a query parameter) and has no use for a page cursor.
type agentGrantView struct {
	ID        string   `json:"id"`
	Scopes    []string `json:"scopes"`
	Depth     string   `json:"depth"`
	Active    bool     `json:"active"`
	ExpiresAt *string  `json:"expires_at,omitempty"`
	RevokedAt *string  `json:"revoked_at,omitempty"`
}

type agentGrantsResponse struct {
	Grants []agentGrantView `json:"grants"`
}

// agentListGrants handles GET /api/agent/grants — store.ListGrants(subject)
// for the AUTHENTICATED agent's own subject (agentFromContext), never a
// subject named in the request (there is nothing in this handler for a
// caller to supply one through in the first place — no query parameter, no
// body).
func (a *API) agentListGrants(w http.ResponseWriter, r *http.Request) {
	subject := agentFromContext(r.Context()).Subject

	grants, err := a.Store.ListGrants(r.Context(), subject)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentListGrants", "could not list grants", err)
		return
	}

	now := time.Now()
	out := agentGrantsResponse{}
	for _, g := range grants {
		out.Grants = append(out.Grants, agentGrantView{
			ID:        g.ID,
			Scopes:    g.Scopes,
			Depth:     g.Depth,
			Active:    g.Active(now),
			ExpiresAt: agentFormatTimePtr(g.ExpiresAt),
			RevokedAt: agentFormatTimePtr(g.RevokedAt),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// agentGrantRequestRequest deliberately has NO subject field — see
// agentSearchRequest's identical doc comment.
type agentGrantRequestRequest struct {
	RequestedScopes []string `json:"requested_scopes"`
	Depth           string   `json:"depth,omitempty"`
	TTLSeconds      int      `json:"ttl_seconds,omitempty"`
	Justification   string   `json:"justification,omitempty"`
}

type agentGrantRequestResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

// agentRequestGrant handles POST /api/agent/grant-requests — the HTTP twin
// of mcptools.request_grant: stages a request a human must explicitly
// approve or deny (store.ApproveGrantRequest/DenyGrantRequest, the reviewer
// REST API); this NEVER creates a real grant. subject is always the
// authenticated agent token's Subject.
func (a *API) agentRequestGrant(w http.ResponseWriter, r *http.Request) {
	subject := agentFromContext(r.Context()).Subject
	ctx := r.Context()

	var req agentGrantRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
		return
	}
	if len(req.RequestedScopes) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("requested_scopes must not be empty"))
		return
	}
	if len(req.RequestedScopes) > agentMaxScopesPerRequest {
		writeError(w, http.StatusBadRequest, fmt.Errorf("requested_scopes exceeds max of %d", agentMaxScopesPerRequest))
		return
	}
	if len(req.Justification) > agentMaxJustificationLength {
		writeError(w, http.StatusBadRequest, fmt.Errorf("justification exceeds max length of %d", agentMaxJustificationLength))
		return
	}
	for _, sc := range req.RequestedScopes {
		if err := scope.Validate(scope.Scope(sc)); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	depth := req.Depth
	if depth == "" {
		depth = "facts"
	}
	if !store.ValidDepth(depth) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("depth must be one of summary, facts, full (got %q)", depth))
		return
	}

	// A negative ttl_seconds is rejected explicitly rather than being
	// treated the same as an omitted one — copied from
	// mcptools.request_grant's identical guard (found in review there: a
	// negative value used to silently fall through the `> 0` check below
	// exactly like an omitted one, turning "an invalid value" into "no
	// expiry requested," the opposite of what the contract promises). Zero
	// is still treated as "omitted": ttl_seconds has no pointer type to
	// distinguish an explicit 0 from a field the caller left out entirely.
	if req.TTLSeconds < 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("ttl_seconds must be positive if provided (got %d)", req.TTLSeconds))
		return
	}
	var ttl *int
	if req.TTLSeconds > 0 {
		ttl = &req.TTLSeconds
	}

	// kind is hardcoded to memory — an agent can't request a capability-kind
	// grant through this endpoint (no such flow exists yet), mirroring
	// mcptools.request_grant's identical stance.
	greq, err := a.Store.RequestGrant(ctx, subject, req.RequestedScopes, string(store.GrantKindMemory), depth, ttl, req.Justification)
	if err != nil {
		writeStoreError(w, http.StatusInternalServerError, "agentRequestGrant", "could not stage grant request", err)
		return
	}
	writeJSON(w, http.StatusCreated, agentGrantRequestResponse{RequestID: greq.ID, Status: string(greq.Status)})
}
