package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/abradner/chuvar/backend/internal/store"
)

// requireAgentAuth authenticates the bearer token against
// store.AuthenticateAgentToken and, on success, attaches the authenticated
// agent's identity to the request context via agentContextKey — mirroring
// requireAuth (api.go) exactly, but against the structurally distinct
// agent_tokens table/hash-namespace (store.AuthenticateAgentToken, not
// AuthenticateReviewerToken) rather than a different check on the same
// credential.
//
// This is one of two layers keeping an agent token from ever reaching a
// reviewer route (or vice versa): the other is that AgentRoutes() is served
// on its own http.Server/listener (cmd/apiserver/main.go, CHUVAR_AGENT_ADDR),
// never mounted alongside Routes(). Auth alone would already reject a
// reviewer token presented here (it doesn't hash-match anything in
// agent_tokens) and an agent token presented to requireAuth (it doesn't
// hash-match anything in reviewer_tokens) — the separate listener means a
// confused or compromised agent process can't even reach the reviewer routes
// at the network layer to try, on top of that rejection.
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

// agentContextKey is an unexported type so this package's context value can
// never collide with a key set by another package or by reviewerContextKey —
// same idiom as reviewerContextKey (api.go), and deliberately a *different*
// key type: an agent token authenticating must never be readable through
// reviewerFromContext (or vice versa), so the two identities can't be
// confused even if a future handler were mistakenly wired to the wrong
// middleware.
type agentContextKey struct{}

// agentFromContext returns the authenticated agent's identity (token ID,
// subject, label), set by requireAgentAuth on every request that reaches a
// handler on AgentRoutes(). Panics if called on a request that bypassed
// requireAgentAuth — every route in AgentRoutes() goes through it, so this is
// a programmer error (a new agent route added outside the auth chain), not a
// runtime condition to handle gracefully. Mirrors reviewerFromContext's
// identical panic idiom.
//
// Subject (never anything from the request body) is what every agent-facing
// handler in agent_routes.go uses to check grants, run searches, and
// attribute audit rows — see that file's package doc comment.
func agentFromContext(ctx context.Context) store.AuthenticatedAgent {
	agent, ok := ctx.Value(agentContextKey{}).(store.AuthenticatedAgent)
	if !ok {
		panic("api: agentFromContext called on a request that bypassed requireAgentAuth")
	}
	return agent
}
