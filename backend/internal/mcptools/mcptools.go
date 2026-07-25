// Package mcptools registers the v0 MCP tool surface: read_with_scope_check,
// propose_write, list_grants. This is intentionally the entire tool surface — no
// deterministic write/delete tool exists here, and none should be added without
// revisiting AGENTS.md §3.1 first.
package mcptools

import (
	"fmt"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/bouncer"
	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/store"
)

// maxScopesPerRequest and maxContentLength bound tool inputs. Nothing about a real
// use of this API needs anywhere near these many scopes or this much text in one
// call — they exist so a malformed or hostile request can't turn scope.Missing's
// O(requested×granted) comparison or an unbounded content/embedding insert into a
// cheap resource-exhaustion lever.
const (
	maxScopesPerRequest = 50
	maxContentLength    = 16384

	// maxQueryLength bounds read_with_scope_check's free-text query, separately
	// from maxContentLength: a search query has no legitimate reason to approach
	// the size of a proposed fact, and it flows into both embedding generation and
	// Postgres's plainto_tsquery — an unbounded query string is a cheap way to
	// force expensive work on both without ever proposing a write.
	maxQueryLength = 1024

	// maxSearchLimit bounds read_with_scope_check's requested result count.
	// store.SearchFacts only normalizes non-positive values to a default of 20; an
	// arbitrarily large positive value passes straight through as a SQL LIMIT,
	// which is cheap authorization-wise (still scope-filtered) but not cheap
	// compute/response-size-wise.
	maxSearchLimit = 200
)

// Register adds all v0 tools to s, all acting as subject.
//
// subject identifies who this server session is authorized to act as, and is
// bound once here rather than accepted as a per-call tool argument. Every v0 tool
// originally took `subject` as a client-supplied JSON field with nothing
// validating it against the actual caller — any MCP client could pass any
// subject string and read/write on that subject's behalf (enumerate their grants,
// read everything they're granted, forge writes attributed to them). That defeated
// the "consent-based, audited" premise the whole project is built on (AGENTS.md
// §1, §3.1) — found in review, not a hypothetical.
//
// Binding subject at server construction instead matches how MCP's stdio transport
// actually deploys: a host application spawns one server process per agent
// session, so the process's own launch environment (see cmd/mcpserver, MCP_SUBJECT)
// is the actual trust boundary, not client-supplied tool arguments. This doesn't
// solve identity for the REST API (internal/api), which legitimately serves many
// human reviewers over HTTP and has its own, still-open gap — see that package's
// comment. Nor does it invent real multi-tenant auth; it closes the one clean,
// narrow hole this transport model has an obvious answer for. A real auth layer
// later replaces "one configured subject" with "subject derived from an
// authenticated session," same shape.
func Register(s *mcp.Server, subject string, st *store.Store, emb embed.Embedder, b *bouncer.Bouncer) {
	registerListGrants(s, subject, st)
	registerReadWithScopeCheck(s, subject, st, emb)
	registerProposeWrite(s, subject, b)
}

// toolError logs the real error server-side and returns a generic, client-facing
// one. Returning err.Error() verbatim from a tool handler puts it straight into the
// MCP response (go-sdk places a returned error into CallToolResult.Content) — that
// would leak raw Postgres/pgx error text (query fragments, column names) to
// whatever agent is calling the tool.
func toolError(op string, err error) error {
	slog.Error("mcptools: internal error", "op", op, "error", err)
	return fmt.Errorf("%s: internal error", op)
}
