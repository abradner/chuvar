package mcptools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/scope"
	"github.com/abradner/chuvar/backend/internal/store"
)

// maxJustificationLength bounds request_grant's free-text justification, same
// resource-exhaustion reasoning as maxContentLength/maxQueryLength in mcptools.go
// — this is display text shown to a human reviewer, not something a real request
// needs to pad out.
const maxJustificationLength = 2048

// validRequestDepths mirrors the CHECK constraint on grant_requests.depth — same
// hand-synced closed-vocabulary stance as store.validDepths.
var validRequestDepths = map[string]bool{"summary": true, "facts": true, "full": true}

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

func registerRequestGrant(s *mcp.Server, subject string, st *store.Store) {
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
		for _, sc := range args.RequestedScopes {
			if err := scope.Validate(scope.Scope(sc)); err != nil {
				return nil, requestGrantOutput{}, fmt.Errorf("request_grant: %w", err)
			}
		}

		depth := args.Depth
		if depth == "" {
			depth = "facts"
		}
		if !validRequestDepths[depth] {
			return nil, requestGrantOutput{}, fmt.Errorf("request_grant: depth must be one of summary, facts, full (got %q)", depth)
		}

		// A negative ttl_seconds used to fall through the `> 0` check below
		// exactly like an omitted one, silently turning "an invalid value" into
		// "no expiry requested" — the opposite of what the tool's own contract
		// promises (omission, not an invalid value, means no expiry). Reject it
		// explicitly instead. Zero is still treated as "omitted": ttl_seconds
		// has no pointer type to distinguish an explicit 0 from a field the
		// caller left out entirely, and 0 is nonsensical either reading.
		// Found in review.
		if args.TTLSeconds < 0 {
			return nil, requestGrantOutput{}, fmt.Errorf("request_grant: ttl_seconds must be positive if provided (got %d)", args.TTLSeconds)
		}
		var ttl *int
		if args.TTLSeconds > 0 {
			ttl = &args.TTLSeconds
		}

		req, err := st.RequestGrant(ctx, subject, args.RequestedScopes, depth, ttl, args.Justification)
		if err != nil {
			return nil, requestGrantOutput{}, toolError("request_grant", err)
		}

		return nil, requestGrantOutput{RequestID: req.ID, Status: string(req.Status)}, nil
	})
}
