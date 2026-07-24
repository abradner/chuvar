package mcptools

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/store"
)

// listGrantsArgs is intentionally empty — subject is bound at server construction
// (see Register's doc comment), not supplied by the caller.
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

func registerListGrants(s *mcp.Server, subject string, st *store.Store) {
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
		grants, err := st.ListGrants(ctx, subject)
		if err != nil {
			return nil, listGrantsOutput{}, toolError("list_grants", err)
		}

		now := time.Now()
		out := listGrantsOutput{}
		for _, g := range grants {
			out.Grants = append(out.Grants, grantView{
				ID:        g.ID,
				Scopes:    g.Scopes,
				Depth:     g.Depth,
				Active:    g.Active(now),
				ExpiresAt: formatTimePtr(g.ExpiresAt),
				RevokedAt: formatTimePtr(g.RevokedAt),
			})
		}
		return nil, out, nil
	})
}

func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}
