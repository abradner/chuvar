package mcptools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
)

// listGrantsArgs is intentionally empty — subject is resolved server-side
// from the agent-class bearer token client carries (see mcptools.go's
// Register doc comment), not supplied by the caller.
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
// client.ListGrants: no request body, map the response onto
// listGrantsOutput. Active/ExpiresAt/RevokedAt all arrive already computed
// (agentGrantView, internal/api/agent_routes.go) — there is no time.Time on
// this side of the wire to compute Active(now) against or format, unlike
// before the cutover.
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
			return nil, listGrantsOutput{}, mapClientError("list_grants", err)
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
