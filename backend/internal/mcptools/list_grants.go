package mcptools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
)

// listGrantsArgs is intentionally empty — subject is resolved server-side
// from client's bearer token (agentFromContext, agent_routes.go), not
// supplied by the caller.
type listGrantsArgs struct{}

type grantView struct {
	ID        string   `json:"id"`
	Scopes    []string `json:"scopes"`
	Depth     string   `json:"depth"`
	Active    bool     `json:"active"`
	ExpiresAt *string  `json:"expires_at,omitempty"`
	RevokedAt *string  `json:"revoked_at,omitempty"`
}

type listGrantsOutput struct {
	Grants []grantView `json:"grants"`
}

// registerListGrants registers list_grants as a thin adapter over
// client.ListGrants, GET /api/agent/grants.
//
// Old -> new mapping (the brief's required diff, for this tool):
//   - st.ListGrants(ctx, subject) — DELETED here, MOVED to agentListGrants
//     (agent_routes.go), which calls the identical store method using the
//     subject its own bearer-token auth resolved, never a client-supplied
//     one. This tool holds no *store.Store to call it with any more.
//   - Active()/formatTimePtr time projection — DELETED here. The server now
//     does this projection (agentFormatTimePtr) and ships ExpiresAt/RevokedAt
//     as already-RFC3339-formatted *string and Active as an already-computed
//     bool; this tool just copies agentclient.GrantView's fields straight
//     across into grantView, which happens to have the identical shape.
//
// There was never any authorization decision in this tool to begin with —
// list_grants only ever returned the caller's own grants — so unlike
// read_with_scope_check there's no scope gate to account for here; the only
// thing that moved is which process runs the one store query.
func registerListGrants(s *mcp.Server, client *agentclient.Client) {
	falsePtr := false
	mcp.AddTool(s, &mcp.Tool{
		Name: "list_grants",
		Description: "List the calling agent's own scope grants, including expired or revoked " +
			"ones. Use this to check what you can currently read before calling read_with_scope_check.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: &falsePtr,
			IdempotentHint:  true,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ listGrantsArgs) (*mcp.CallToolResult, listGrantsOutput, error) {
		res, err := client.ListGrants(ctx)
		if err != nil {
			return nil, listGrantsOutput{}, toolError("list_grants", err)
		}

		out := listGrantsOutput{}
		for _, g := range res.Grants {
			out.Grants = append(out.Grants, grantView{
				ID:        g.ID,
				Scopes:    g.Scopes,
				Depth:     g.Depth,
				Active:    g.Active,
				ExpiresAt: g.ExpiresAt,
				RevokedAt: g.RevokedAt,
			})
		}
		return nil, out, nil
	})
}
