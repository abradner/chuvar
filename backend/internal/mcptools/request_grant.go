package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
)

// maxJustificationLength bounds request_grant's free-text justification, same
// resource-exhaustion reasoning as maxContentLength/maxQueryLength in mcptools.go
// — this is display text shown to a human reviewer, not something a real request
// needs to pad out. Mirrors agent_routes.go's agentMaxJustificationLength.
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
// client.RequestGrant, POST /api/agent/grant-requests.
//
// Old -> new mapping (the brief's required diff, for this tool):
//   - The justification length cap — STILL HERE, client-side, as a courtesy;
//     agentRequestGrant re-enforces it server-side regardless.
//   - The requested_scopes count cap — STILL HERE, same reasoning.
//   - The empty-requested_scopes check, per-scope scope.Validate, the
//     depth-default-to-"facts" + store.ValidDepth check, and the
//     negative-ttl_seconds rejection — ALL DELETED here. None of these are
//     size caps, they're domain validation, and agentRequestGrant
//     (agent_routes.go) already reproduces every one of them line for line —
//     including the negative-ttl_seconds check's own "must not silently
//     collapse to no-expiry" reasoning. A caller that gets any of these
//     wrong now finds out one HTTP round trip later than it used to, via the
//     server's 400 (*agentclient.ValidationError, returned verbatim below)
//     instead of a local error — same externally-visible outcome (a tool
//     error mentioning the real problem), one fewer place the rule is
//     encoded.
//   - st.RequestGrant(ctx, subject, ...) — DELETED here, MOVED to
//     agentRequestGrant, which calls the identical store method using the
//     subject its own bearer-token auth resolved. This tool holds no
//     *store.Store to call it with any more.
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
			var verr *agentclient.ValidationError
			if errors.As(err, &verr) {
				return nil, requestGrantOutput{}, verr
			}
			return nil, requestGrantOutput{}, toolError("request_grant", err)
		}

		return nil, requestGrantOutput{RequestID: res.RequestID, Status: res.Status}, nil
	})
}
