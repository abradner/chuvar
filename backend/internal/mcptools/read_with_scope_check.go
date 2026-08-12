package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
)

type readArgs struct {
	Query           string   `json:"query" jsonschema:"free-text search query, max 1024 characters"`
	RequestedScopes []string `json:"requested_scopes" jsonschema:"scopes this query is expected to touch, checked against your grants before any search runs"`
	Limit           int      `json:"limit,omitempty" jsonschema:"max facts to return, default 20, max 200"`
}

// factView mirrors agentclient.Fact field-for-field — the response shape this
// tool has always returned, kept identical across the cutover (the brief's
// "existing, unchanged output types") even though the request now goes over
// HTTP instead of directly against store.Store.
type factView struct {
	ID         string              `json:"id"`
	Content    string              `json:"content,omitempty"`
	Summary    string              `json:"summary,omitempty"`
	Depth      string              `json:"depth"`
	Scopes     []string            `json:"scopes"`
	Provenance *factProvenanceView `json:"provenance,omitempty"`
}

// factProvenanceView mirrors agentclient.FactProvenance field-for-field.
// Times arrive already formatted as RFC3339 strings from the server (see
// agent_routes.go's agentFormatTimePtr) — this tool no longer does any of its
// own time formatting, unlike the pre-cutover version, because it no longer
// touches a store.Fact with real time.Time fields at all.
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
// adapter over client.Search, POST /api/agent/search.
//
// Old -> new mapping (the brief's required diff, for this tool):
//   - Input caps (requested_scopes count, query length, limit) — STILL HERE,
//     client-side, as a courtesy; agentSearch re-enforces every one of them
//     server-side regardless (agent_routes.go's agentMax* constants).
//   - Per-scope format validation (scope.Validate) — DELETED here. Not a
//     resource cap, so it doesn't get the courtesy-duplication treatment; the
//     server validates every requested scope and returns a 400 the caller
//     sees verbatim (decodeValidationError -> *agentclient.ValidationError ->
//     returned as-is below), so a malformed scope still surfaces as a tool
//     error, just via a round trip instead of a local check.
//   - The scope gate itself (fetch GrantedScopeDepths, compute scope.Missing,
//     audit "insufficient_scope" if anything's missing) — DELETED here,
//     MOVED to agentSearch (agent_routes.go), which is now the only place
//     this authorization decision is made. This tool no longer imports
//     internal/store or internal/scope at all.
//   - The embed call (emb.Embed) — DELETED here, MOVED to agentSearch. This
//     process never sees an Embedder; embedding happens entirely
//     server-side, inside the same request agentSearch handles.
//   - The revoke-during-embed re-check (re-fetch GrantedScopeDepths after
//     Embed, before SearchFacts) — DELETED here, MOVED to agentSearch. This
//     is the property named in the brief as the actual risk: it only stays a
//     real gate because agentSearch runs the whole pre-embed-check ->
//     embed -> post-embed-recheck -> search sequence inside one handler, atomic
//     from this client's perspective (see that file's own doc comment on why
//     no piece of it may be split across the HTTP boundary). This tool now
//     just makes one HTTP call and trusts the single JSON response it gets
//     back — there is no window here for it to reopen, because there is
//     nothing left here to have a window.
//   - The disclosure audit ("read" event, per-fact depth detail) — DELETED
//     here, MOVED to agentSearch, which writes it using the subject its own
//     bearer-token auth resolved (agentFromContext), not anything this tool
//     could supply.
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
			// Only a *agentclient.ValidationError (the server's own 400 message,
			// e.g. a malformed scope) is safe to show the calling agent
			// verbatim — see agentclient.ValidationError's doc comment for why
			// that's true of every 400 this server sends. Everything else
			// (ErrUnauthorized, a 5xx serverError, a transport failure) is
			// masked, same allowlist-not-denylist stance propose_write.go's
			// pre-cutover version already documented for its own error taxonomy.
			var verr *agentclient.ValidationError
			if errors.As(err, &verr) {
				return nil, readOutput{}, verr
			}
			return nil, readOutput{}, toolError("read_with_scope_check", err)
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
