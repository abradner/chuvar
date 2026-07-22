// Package mcptools registers the v0 MCP tool surface: read_with_scope_check,
// propose_write, list_grants. This is intentionally the entire tool surface — no
// deterministic write/delete tool exists here, and none should be added without
// revisiting AGENTS.md §3.1 first.
package mcptools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"memoryvault/internal/bouncer"
	"memoryvault/internal/embed"
	"memoryvault/internal/store"
)

// Register adds all v0 tools to s.
func Register(s *mcp.Server, st *store.Store, emb embed.Embedder, b *bouncer.Bouncer) {
	registerListGrants(s, st)
	registerReadWithScopeCheck(s, st, emb)
	registerProposeWrite(s, b)
}
