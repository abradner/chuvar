package agentclient

import "fmt"

// ErrUnauthorized is returned (wrapped, so errors.Is(err, ErrUnauthorized)
// works) whenever the agent-facing API responds 401 to a request carrying
// this Client's token. A later PR (mcpserver becoming an HTTP client of
// AgentRoutes, ticket E3) uses this to fail fast at process boot per
// CLAUDE.md principle 5 ("fail closed, loudly") — a bad, missing, or revoked
// agent token must abort startup with an unmistakable error, never limp
// forward and fail every subsequent call silently one at a time.
var ErrUnauthorized = fmt.Errorf("agentclient: unauthorized")

// ValidationError carries a 400 response's error message verbatim. The
// agent-facing API only ever puts its own constructed text in a 400 body
// (agent_routes.go uses writeError, never writeStoreError, for every 400 it
// returns) — never raw driver/store detail — so passing Message straight
// through to the caller is safe and, per the brief, is the point: it's
// validation feedback the calling agent is meant to see and act on (e.g.
// "requested_scopes exceeds max of 50").
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// serverError is returned for a 5xx response or any status this client
// doesn't otherwise special-case, and for transport-level failures (Do
// itself erroring). Deliberately generic: a 5xx's body is whatever
// writeStoreError put there for a human reviewing logs, not something meant
// for an agent to parse, and a transport error's text can carry local
// filesystem/DNS/proxy detail that has no business in an agent-visible
// error message. Op and Status identify *where* the failure was, which is
// enough for a caller to log and retry/alert on, without echoing anything
// the server (or the local network stack) said.
type serverError struct {
	Op     string
	Status int
}

func (e *serverError) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("agentclient: %s: request failed", e.Op)
	}
	return fmt.Sprintf("agentclient: %s: server error (status %d)", e.Op, e.Status)
}
