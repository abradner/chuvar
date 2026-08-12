// Agent-facing HTTP surface (this file, agent_auth.go, agent_search.go,
// agent_proposals.go, agent_grants.go): the HTTP counterpart to
// internal/mcptools' MCP tools, for the same agent identity but reached over
// HTTP instead of stdio. A later PR makes cmd/mcpserver a pure HTTP client
// of these routes and deletes internal/mcptools' own copy of this logic; the
// duplication between the two packages until then is deliberate and
// temporary — see agent_search.go's doc comment. Do not import
// internal/mcptools from this package, or vice versa, and do not modify
// internal/mcptools in this batch.
package api

import "net/http"

// The agentMax* constants bound agent-endpoint inputs, mirroring
// internal/mcptools/mcptools.go's maxScopesPerRequest/maxContentLength/
// maxQueryLength/maxSearchLimit and request_grant.go's
// maxJustificationLength — same values, same resource-exhaustion reasoning
// (an unbounded requested_scopes list turns scope.Missing's
// O(requested×granted) comparison into a cheap DoS lever; an unbounded query
// forces expensive embedding/full-text work; etc.). Duplicated rather than
// imported: mcptools' constants are unexported, and this whole file set is
// itself a deliberate temporary duplicate — see the package comment above.
const (
	agentMaxScopesPerRequest    = 50
	agentMaxContentLength       = 16384
	agentMaxQueryLength         = 1024
	agentMaxSearchLimit         = 200
	agentMaxJustificationLength = 2048
)

// AgentRoutes builds the mux for the agent-facing surface — the counterpart
// to Routes() for the human-reviewer surface. It applies the SAME shared
// middleware chain as Routes() (cors, limitBody, withRequestTimeout) but a
// DIFFERENT auth gate: requireAgentAuth instead of requireAuth, since these
// routes authenticate a structurally distinct credential (agent_tokens, not
// reviewer_tokens — see requireAgentAuth's doc comment).
//
// Critically, the handler this returns MUST be served on a separate
// net.Listener/http.Server from Routes() — never mounted onto the same
// http.Server, and never reachable through it. cmd/apiserver binds it on its
// own address (CHUVAR_AGENT_ADDR, config.Config). This is deliberate
// defense in depth on top of (never instead of) the auth gate itself: an
// agent process holding a valid agent token but no network route to the
// reviewer listener cannot reach a reviewer-only mutation even if some
// future bug in requireAgentAuth let a malformed or forged credential
// through, and symmetrically a reviewer token presented here is simply
// rejected (AuthenticateAgentToken never matches a reviewer_tokens row) —
// see agent_auth_test.go's confused-deputy tests for both directions.
func (a *API) AgentRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent/search", a.agentSearch)
	mux.HandleFunc("POST /api/agent/proposals", a.agentPropose)
	mux.HandleFunc("GET /api/agent/grants", a.agentListGrants)
	mux.HandleFunc("POST /api/agent/grant-requests", a.agentRequestGrant)
	mux.HandleFunc("GET /api/agent/whoami", a.agentWhoami)

	return a.cors(a.requireAgentAuth(a.limitBody(a.withRequestTimeout(mux))))
}

type agentWhoamiResponse struct {
	Subject string `json:"subject"`
}

// agentWhoami handles GET /api/agent/whoami — a boot health check a later PR
// uses to let mcpserver confirm its token authenticates before serving any
// MCP tool calls. Subject always comes from the authenticated agent token
// (agentFromContext), never anything client-supplied — there is nothing in
// the request for a caller to spoof here in the first place.
func (a *API) agentWhoami(w http.ResponseWriter, r *http.Request) {
	agent := agentFromContext(r.Context())
	writeJSON(w, http.StatusOK, agentWhoamiResponse{Subject: agent.Subject})
}
