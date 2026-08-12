package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/abradner/chuvar/backend/internal/store"
)

// requireAgentAuth authenticates the bearer token against
// store.AuthenticateAgentToken and, on success, attaches the authenticated
// agent's identity to the request context via agentFromContext — every
// AgentRoutes handler reads the acting subject from there, never from the
// request body (see agent_search.go/agent_proposals.go/agent_grants.go's
// doc comments).
//
// This mirrors requireAuth (api.go) exactly in shape, but authenticates
// against a structurally distinct credential: agent_tokens, not
// reviewer_tokens (see store.AgentToken's doc comment) — an agent token can
// never satisfy requireAuth, and a reviewer token can never satisfy this.
// That alone is not the whole isolation story: AgentRoutes must also be
// served on a SEPARATE net.Listener from Routes() (cmd/apiserver's
// CHUVAR_AGENT_ADDR), so a bug in this auth check couldn't, by itself, make
// a reviewer route reachable from agent context — see AgentRoutes' doc
// comment for the network-layer half of this control.
func (a *API) requireAgentAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) {
			writeError(w, http.StatusUnauthorized, errUnauthorized)
			return
		}
		agent, ok, err := a.Store.AuthenticateAgentToken(r.Context(), strings.TrimPrefix(auth, prefix))
		if err != nil {
			writeStoreError(w, http.StatusInternalServerError, "requireAgentAuth", "could not authenticate", err)
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, errUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), agentContextKey{}, agent)))
	})
}

// agentContextKey is an unexported type so this package's agent context
// value can never collide with reviewerContextKey (api.go) or a key set by
// another package — same idiom, same reasoning as reviewerContextKey.
type agentContextKey struct{}

// agentFromContext returns the authenticated agent's identity, set by
// requireAgentAuth on every request that reaches a handler. Panics if called
// on a request that bypassed requireAgentAuth — every route in AgentRoutes()
// does, so this is a programmer error (a new agent route added outside the
// auth chain), not a runtime condition to handle gracefully. Mirrors
// reviewerFromContext exactly.
func agentFromContext(ctx context.Context) store.AuthenticatedAgent {
	agent, ok := ctx.Value(agentContextKey{}).(store.AuthenticatedAgent)
	if !ok {
		panic("api: agentFromContext called on a request that bypassed requireAgentAuth")
	}
	return agent
}
