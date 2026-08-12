package mcptools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
)

// maxJustificationLength bounds request_grant's free-text justification —
// courtesy client-side cap only, matching maxScopesPerRequest/maxContentLength/
// maxQueryLength in mcptools.go; agent_routes.go's agentMaxJustificationLength
// re-enforces the same bound server-side regardless of what this client sends.
const maxJustificationLength = 2048

type requestGrantArgs struct {
	RequestedScopes []string `json:"requested_scopes" jsonschema:"scopes you're asking to be granted"`
	Depth           string   `json:"depth,omitempty" jsonschema:"summary, facts, or full; defaults to facts"`
	TTLSeconds      int      `json:"ttl_seconds,omitempty" jsonschema:"how long the grant should last if approved; omit for no expiry"`
	Justification   string   `json:"justification,omitempty" jsonschema:"why you need this access, shown to the human reviewer, max 2048 characters"`
}

type requestGrantOutput struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

// registerRequestGrant registers request_grant as a thin adapter over
// client.RequestGrant: marshal args into an agentclient.GrantRequestRequest,
// call the agent API, map the response onto requestGrantOutput.
//
// Semantic validation this tool used to run itself — scope.Validate against
// each requested scope, the depth enum check (store.ValidDepth), and
// rejecting a negative ttl_seconds as distinct from an omitted one (found in
// review, pre-cutover) — is deleted, not relocated: agentRequestGrant
// (internal/api/agent_routes.go) reproduces every one of those checks
// server-side, byte-for-byte, and is the sole place they now run. Only the
// size caps stay here, as a courtesy (see maxJustificationLength/
// maxScopesPerRequest's doc comments) — the server re-enforces those too.
func registerRequestGrant(s *mcp.Server, client *agentclient.Client) {
	falsePtr := false
	mcp.AddTool(s, &mcp.Tool{
		Name: "request_grant",
		Description: "Ask a human to grant you additional scopes. This NEVER grants access directly — it " +
			"stages a request that a human must explicitly approve (or deny) before it becomes a real, " +
			"usable grant. Use this after read_with_scope_check returns status=insufficient_scope, or " +
			"whenever you know in advance you'll need scopes you don't currently hold.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: &falsePtr, // stages a request, never mutates a real grant
			IdempotentHint:  false,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args requestGrantArgs) (*mcp.CallToolResult, requestGrantOutput, error) {
		if len(args.RequestedScopes) == 0 {
			return nil, requestGrantOutput{}, fmt.Errorf("request_grant: requested_scopes must not be empty")
		}
		if len(args.RequestedScopes) > maxScopesPerRequest {
			return nil, requestGrantOutput{}, fmt.Errorf("request_grant: requested_scopes exceeds max of %d", maxScopesPerRequest)
		}
		if len(args.Justification) > maxJustificationLength {
			return nil, requestGrantOutput{}, fmt.Errorf("request_grant: justification exceeds max length of %d", maxJustificationLength)
		}

		res, err := client.RequestGrant(ctx, agentclient.GrantRequestRequest{
			RequestedScopes: args.RequestedScopes,
			Depth:           args.Depth,
			TTLSeconds:      args.TTLSeconds,
			Justification:   args.Justification,
		})
		if err != nil {
			return nil, requestGrantOutput{}, mapClientError("request_grant", err)
		}

		return nil, requestGrantOutput{RequestID: res.RequestID, Status: res.Status}, nil
	})
}
