// Package mcptools registers the v0 MCP tool surface: read_with_scope_check,
// propose_write, list_grants, request_grant. This is intentionally the entire
// tool surface — no deterministic write/delete tool exists here, and none should
// be added without revisiting AGENTS.md §3.1 first. request_grant follows the same
// shape as propose_write: it stages a request, never creates a real grant — only
// a human, via the REST API, does that (store.ApproveGrantRequest).
//
// Cutover (ticket E3, #82/#86 PR 4): every tool used to hold a *store.Store, an
// embed.Embedder and a *bouncer.Bouncer, and ran the scope gate, the embed call,
// and the revoke-during-embed re-check inline — i.e. mcpserver, which runs
// inside an agent's own process tree, held a live DATABASE_URL and did database
// orchestration directly (AGENTS.md §3.0/§3.6's "residual gap"). That is gone.
// Every tool here is now a thin adapter: marshal args, call one
// *agentclient.Client method, map the typed response onto the same output
// types this package has always exposed. The scope gate, the embed call, and
// the post-embed re-check all still happen — exactly once, server-side, in
// internal/api/agent_routes.go — never duplicated here (CLAUDE.md principle 7,
// one chokepoint per property). Deleting them from this package is the point
// of the cutover, not a regression: see agent_routes.go's package doc comment
// for why that whole sequence has to run inside one server-side handler.
package mcptools

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
)

// maxScopesPerRequest, maxContentLength, maxQueryLength, maxSearchLimit, and
// maxJustificationLength (request_grant.go) bound tool inputs client-side, as
// a courtesy: rejecting an obviously-oversized request here saves a network
// round trip to the agent API. They are not the enforcement — agent_routes.go
// re-checks every one of these against the identical constants
// (agentMaxScopesPerRequest etc.) server-side regardless of what this client
// sends, because a client (or a modified/malicious build of this binary) is
// not a trust boundary. Values match agent_routes.go's exactly so a rejection
// here and a rejection there read the same to whoever's debugging it.
const (
	maxScopesPerRequest = 50
	maxContentLength    = 16384

	// maxQueryLength bounds read_with_scope_check's free-text query, separately
	// from maxContentLength — see agent_routes.go's identical constant for the
	// full reasoning (a search query flowing into both embedding generation and
	// Postgres's plainto_tsquery is a cheap way to force expensive work).
	maxQueryLength = 1024

	// maxSearchLimit bounds read_with_scope_check's requested result count.
	maxSearchLimit = 200
)

// Register adds all v0 tools to s, backed by client — an HTTP client of
// internal/api's agent-facing surface (agent_routes.go), authenticated with a
// single agent-class bearer token (see internal/agentclient's package doc
// comment). This replaces the pre-cutover shape, which took `subject` plus a
// *store.Store, an embed.Embedder and a *bouncer.Bouncer and ran every tool's
// database work in this process.
//
// Identity used to be bound here at server construction (a `subject` string
// read from cmd/mcpserver's MCP_SUBJECT environment variable) rather than
// accepted as a per-call tool argument — see this function's pre-cutover doc
// comment in git history for why a client-supplied subject was the original
// v0 hole. The cutover replaces that binding with something strictly
// stronger: subject is no longer read from this process's environment at
// all. It is resolved server-side, once per request, from whichever
// agent-class token client.Token carries (store.AuthenticateAgentToken,
// agent_auth.go's agentFromContext) — a real, individually-revocable
// credential rather than a trusted environment variable. Every tool call this
// package makes authenticates itself the same way; there is nothing left
// here for a caller to spoof, because there is no subject-shaped argument
// anywhere in this package's tool schemas.
func Register(s *mcp.Server, client *agentclient.Client) {
	registerListGrants(s, client)
	registerReadWithScopeCheck(s, client)
	registerProposeWrite(s, client)
	registerRequestGrant(s, client)
}

// toolError logs the real error server-side (from mcpserver's own
// perspective — "server-side" relative to the calling agent, even though
// mcpserver is itself now a client of the actual backend) and returns a
// generic, client-facing one. Returning err.Error() verbatim from a tool
// handler puts it straight into the MCP response (go-sdk places a returned
// error into CallToolResult.Content) — that would leak agentclient's own
// wrapped detail (which HTTP status, which endpoint) to whatever agent is
// calling the tool, the same class of leak this masking closed before the
// cutover for raw Postgres/pgx error text.
func toolError(op string, err error) error {
	slog.Error("mcptools: internal error", "op", op, "error", err)
	return fmt.Errorf("%s: internal error", op)
}

// mapClientError translates an error returned by an agentclient.Client call
// into what a tool handler should return to the caller. A
// *agentclient.ValidationError carries agent_routes.go's own constructed 400
// message verbatim (never raw store/driver detail — see that type's doc
// comment) — safe and useful to show the calling agent, exactly the same
// "verbatim" treatment this package gave bouncer.ValidationError and its own
// scope.Validate/length-cap errors before the cutover. Everything else
// (agentclient.ErrUnauthorized, a 5xx serverError, a transport failure) is
// masked through toolError: none of those are actionable for the calling
// agent to fix by changing its input, and an unauthorized/unreachable-backend
// detail is exactly the kind of operator-facing information toolError exists
// to keep off the wire. This is an allowlist, not a denylist, matching
// propose_write.go's pre-cutover errors.As stance: only the one error shape
// positively identified as safe passes through unmasked.
func mapClientError(op string, err error) error {
	var verr *agentclient.ValidationError
	if errors.As(err, &verr) {
		return verr
	}
	return toolError(op, err)
}
