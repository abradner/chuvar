// Package mcptools registers the v0 MCP tool surface: read_with_scope_check,
// propose_write, list_grants, request_grant. This is intentionally the entire
// tool surface — no deterministic write/delete tool exists here, and none should
// be added without revisiting AGENTS.md §3.1 first. request_grant follows the same
// shape as propose_write: it stages a request, never creates a real grant — only
// a human, via the REST API, does that (store.ApproveGrantRequest).
//
// Every tool here is a thin adapter over internal/agentclient — mcpserver's own
// process holds no database credential and no store.Store (ticket E3, AGENTS.md
// §3.6): each tool marshals its args, calls the one HTTP method on
// *agentclient.Client that mirrors it, and maps the response onto this package's
// unchanged output types. This is a deliberate, one-way cutover: the DB
// orchestration these tools used to run directly — the scope gate (checking
// GrantedScopeDepths and computing missing scopes), the embed call, and the
// revoke-during-embed re-check — has moved server-side, into
// internal/api/agent_routes.go's agentSearch handler, and is NOT reproduced
// here. That handler is now the single chokepoint for that sequence (CLAUDE.md
// principle 7); duplicating it here again would just recreate the two-copies
// problem PR 2 introduced on the way to this cutover. See each tool file's own
// comment for the specific old-code -> new-location mapping.
package mcptools

import (
	"fmt"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
)

// maxScopesPerRequest, maxContentLength, maxQueryLength, maxSearchLimit, and
// maxJustificationLength (request_grant.go) mirror
// internal/api/agent_routes.go's agentMax* constants exactly. Kept here too,
// even though the server re-enforces every one of them independently, purely
// as a courtesy: rejecting an obviously-oversized request locally saves a
// round trip to the backend rather than making the network do the work of
// telling the caller "no." They are not a security boundary — the server-side
// checks are (see that file's own doc comment for why duplicating input caps,
// as opposed to the authorization logic around them, is fine to leave on both
// sides).
const (
	maxScopesPerRequest = 50
	maxContentLength    = 16384
	maxQueryLength      = 1024
	maxSearchLimit      = 200
)

// Register adds all v0 tools to s, each backed by client.
//
// Register used to take `subject` and bind it once at server construction,
// because with the old direct-DB design, whoever launched this process was
// the trust boundary the tools had no other way to check (see this
// function's git history for the fuller version of that reasoning — subject
// used to be a client-supplied tool argument with nothing validating it,
// found in review, then fixed by binding it server-process-wide instead).
// That reasoning has now moved one hop further out: client carries a bearer
// agent-class token (store.AuthenticateAgentToken), and every request it
// sends is authenticated by internal/api's requireAgentAuth, which derives
// the acting subject from that token — never from anything this process
// sends in a request body (agent_routes.go's package doc comment). mcpserver
// itself no longer needs to know or assert a subject at all; it just holds
// one credential and lets the server resolve who that credential belongs to,
// on every call, same as any other HTTP client of an authenticated API.
func Register(s *mcp.Server, client *agentclient.Client) {
	registerListGrants(s, client)
	registerReadWithScopeCheck(s, client)
	registerProposeWrite(s, client)
	registerRequestGrant(s, client)
}

// toolError logs the real error server-side and returns a generic, client-facing
// one. Returning err.Error() verbatim from a tool handler puts it straight into the
// MCP response (go-sdk places a returned error into CallToolResult.Content) — that
// would leak agentclient's own internal detail (a transport failure's underlying
// text, an unexpected status code) to whatever agent is calling the tool. The one
// case that IS safe to return verbatim is *agentclient.ValidationError — see each
// tool's own errors.As branch, which returns that one directly instead of routing
// it through toolError.
func toolError(op string, err error) error {
	slog.Error("mcptools: internal error", "op", op, "error", err)
	return fmt.Errorf("%s: internal error", op)
}
