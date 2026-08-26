package mcptools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
)

type readArgs struct {
	Query           string   `json:"query" jsonschema:"free-text search query, max 1024 characters"`
	RequestedScopes []string `json:"requested_scopes" jsonschema:"scopes this query is expected to touch, checked against your grants before any search runs"`
	Limit           int      `json:"limit,omitempty" jsonschema:"max facts to return, default 20, max 200"`
}

// factView projects a Fact through the depth of the grant(s) that authorized
// returning it: Content is set at "facts" or "full" depth, Summary at
// "summary" depth — never both, and Depth reports which one applies so a
// caller can tell "no summary" (empty Summary at summary depth, e.g. a
// pre-migration fact with none generated yet) apart from "not summary depth"
// (empty Summary because Content was returned instead).
//
// Provenance is "full" depth's own addition on top of "facts": the ladder was
// designed as summary → facts → *full provenance* (the init migration's
// "progressive disclosure per Notion §3"), so "full" adds a fact's provenance
// to its content rather than more content. This type, and the depth ladder it
// encodes, is unchanged by the cutover (ticket E3) — see mcptools.go's
// package doc comment: what changed is how a factView gets populated
// (agentclient.Fact off the wire, not a direct store.Fact), never its shape.
// Shipping decided_by here discloses a human's identity (who approved the
// diff that produced this fact), which the fact's content alone never does —
// exactly why this is its own grant level rather than folded into "facts".
type factView struct {
	ID         string              `json:"id"`
	Content    string              `json:"content,omitempty"`
	Summary    string              `json:"summary,omitempty"`
	Depth      string              `json:"depth"`
	Scopes     []string            `json:"scopes"`
	Provenance *factProvenanceView `json:"provenance,omitempty"`
}

// factProvenanceView is the JSON shape of a "full"-depth fact's provenance.
// Times arrive as already-formatted RFC3339 strings from agentclient.Fact —
// agent_routes.go formats them server-side (its own agentFormatTimePtr),
// so there is no time.Time to parse or reformat on this side of the wire
// anymore.
type factProvenanceView struct {
	SourceStagedDiffID string  `json:"source_staged_diff_id"`
	DecidedBy          *string `json:"decided_by,omitempty"`
	DecidedAt          *string `json:"decided_at,omitempty"`
	SupersededBy       *string `json:"superseded_by,omitempty"`
	CreatedAt          string  `json:"created_at"`
	ValidAt            string  `json:"valid_at"`
	InvalidAt          *string `json:"invalid_at,omitempty"`
	ExpiredAt          *string `json:"expired_at,omitempty"`
}

type readOutput struct {
	// Status is "ok" or "insufficient_scope". Kept as a string field (rather than a
	// bare error) because insufficient_scope is an expected, structured outcome the
	// caller is meant to act on — request the missing grant — not a failure.
	Status        string     `json:"status"`
	Facts         []factView `json:"facts,omitempty"`
	MissingScopes []string   `json:"missing_scopes,omitempty"`
}

// registerReadWithScopeCheck registers read_with_scope_check as a thin
// adapter over client.Search: marshal args into an agentclient.SearchRequest,
// call the agent API, map the response onto readOutput.
//
// Everything that used to happen in this function's body — fetching granted
// scope depths, running scope.Missing, calling the embedder, re-fetching
// granted scope depths after Embed to close the revoke-during-embed race,
// calling store.SearchFacts, and writing the disclosure audit row — is
// deleted, not relocated to a helper. It now runs exactly once, server-side,
// in agentSearch (internal/api/agent_routes.go), inside one handler for the
// same reason it used to run inside one tool call: scope-before-rank has to
// stay atomic against a grant changing mid-request, which requires the embed
// call and both scope checks to happen in the same process as the search
// itself. See that file's package doc comment for the full argument; the
// mid-embed-revocation regression test that used to live in this package
// (TestReadWithScopeCheck_RevokedMidEmbedIsRejected) now lives there too, as
// TestAgentSearch_RevokedMidEmbedIsRejected.
func registerReadWithScopeCheck(s *mcp.Server, client *agentclient.Client) {
	falsePtr := false
	mcp.AddTool(s, &mcp.Tool{
		Name: "read_with_scope_check",
		Description: "Search memory for facts matching a query. Checks requested_scopes against your " +
			"active grants before running any search; if scopes are missing, returns " +
			"status=insufficient_scope naming exactly which scopes a human would need to grant, and " +
			"runs no search. The actual result set is always filtered by your full granted scopes " +
			"(not just requested_scopes) — a fact is only returned if every one of its scope tags is " +
			"covered by a grant.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: &falsePtr,
			IdempotentHint:  true,
			OpenWorldHint:   &falsePtr,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args readArgs) (*mcp.CallToolResult, readOutput, error) {
		if len(args.RequestedScopes) > maxScopesPerRequest {
			return nil, readOutput{}, fmt.Errorf("read_with_scope_check: requested_scopes exceeds max of %d", maxScopesPerRequest)
		}
		if len(args.Query) > maxQueryLength {
			return nil, readOutput{}, fmt.Errorf("read_with_scope_check: query exceeds max length of %d", maxQueryLength)
		}
		if args.Limit > maxSearchLimit {
			return nil, readOutput{}, fmt.Errorf("read_with_scope_check: limit exceeds max of %d", maxSearchLimit)
		}

		res, err := client.Search(ctx, agentclient.SearchRequest{
			Query:           args.Query,
			RequestedScopes: args.RequestedScopes,
			Limit:           args.Limit,
		})
		if err != nil {
			return nil, readOutput{}, mapClientError("read_with_scope_check", err)
		}

		out := readOutput{Status: res.Status, MissingScopes: res.MissingScopes}
		for _, f := range res.Facts {
			fv := factView{ID: f.ID, Content: f.Content, Summary: f.Summary, Depth: f.Depth, Scopes: f.Scopes}
			if f.Provenance != nil {
				p := f.Provenance
				fv.Provenance = &factProvenanceView{
					SourceStagedDiffID: p.SourceStagedDiffID,
					DecidedBy:          p.DecidedBy,
					DecidedAt:          p.DecidedAt,
					SupersededBy:       p.SupersededBy,
					CreatedAt:          p.CreatedAt,
					ValidAt:            p.ValidAt,
					InvalidAt:          p.InvalidAt,
					ExpiredAt:          p.ExpiredAt,
				}
			}
			out.Facts = append(out.Facts, fv)
		}
		return nil, out, nil
	})
}
