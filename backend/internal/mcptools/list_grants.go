package mcptools

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"memoryvault/internal/store"
)

type listGrantsArgs struct {
	Subject string `json:"subject" jsonschema:"the agent/client identity whose grants to list"`
}

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

func registerListGrants(s *mcp.Server, st *store.Store) {
	falsePtr := false
	mcp.AddTool(s, &mcp.Tool{
		Name: "list_grants",
		Description: "List the scope grants held by a subject (agent/client identity), including " +
			"expired or revoked ones. Use this to check what a subject can currently read before " +
			"calling read_with_scope_check, or to show a human what access an agent has.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: &falsePtr,
			IdempotentHint:  true,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args listGrantsArgs) (*mcp.CallToolResult, listGrantsOutput, error) {
		grants, err := st.ListGrants(ctx, args.Subject)
		if err != nil {
			return nil, listGrantsOutput{}, fmt.Errorf("list_grants: %w", err)
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
