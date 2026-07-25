package mcptools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/embed"
	"github.com/abradner/chuvar/backend/internal/scope"
	"github.com/abradner/chuvar/backend/internal/store"
)

type readArgs struct {
	Query           string   `json:"query" jsonschema:"free-text search query, max 1024 characters"`
	RequestedScopes []string `json:"requested_scopes" jsonschema:"scopes this query is expected to touch, checked against your grants before any search runs"`
	Limit           int      `json:"limit,omitempty" jsonschema:"max facts to return, default 20, max 200"`
}

// factView's Content is always the fact's full, real content, regardless of the
// grant's depth (summary/facts/full — internal/store's Grant.Depth, validated and
// stored but not read anywhere in this file). Depth is not enforced today: a
// "summary" grant currently exposes exactly the same content as "full." That's a
// real gap, not a design choice, flagged in review — closing it needs a product
// decision this project hasn't made (what does a summary actually contain — a
// truncation? A separately generated field? Metadata-only?), so it's left
// documented here rather than guessed at with placeholder semantics that might not
// match whatever the real answer turns out to be.
type factView struct {
	ID      string   `json:"id"`
	Content string   `json:"content"`
	Scopes  []string `json:"scopes"`
}

type readOutput struct {
	// Status is "ok" or "insufficient_scope". Kept as a string field (rather than a
	// bare error) because insufficient_scope is an expected, structured outcome the
	// caller is meant to act on — request the missing grant — not a failure.
	Status        string     `json:"status"`
	Facts         []factView `json:"facts,omitempty"`
	MissingScopes []string   `json:"missing_scopes,omitempty"`
}

func registerReadWithScopeCheck(s *mcp.Server, subject string, st *store.Store, emb embed.Embedder) {
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
		requested := toScopes(args.RequestedScopes)
		for _, r := range requested {
			if err := scope.Validate(r); err != nil {
				return nil, readOutput{}, fmt.Errorf("read_with_scope_check: %w", err)
			}
		}

		grantedStrs, err := st.GrantedScopes(ctx, subject)
		if err != nil {
			return nil, readOutput{}, toolError("read_with_scope_check", err)
		}
		granted := toScopes(grantedStrs)

		if missing := scope.Missing(requested, granted); len(missing) > 0 {
			missingStrs := fromScopes(missing)
			if err := st.LogAudit(ctx, "insufficient_scope", subject, nil, nil, nil, missingStrs); err != nil {
				return nil, readOutput{}, toolError("read_with_scope_check", err)
			}
			return nil, readOutput{Status: "insufficient_scope", MissingScopes: missingStrs}, nil
		}

		limit := args.Limit
		if limit <= 0 {
			limit = 20
		}

		var queryVec []float32
		if emb != nil {
			queryVec, err = emb.Embed(ctx, args.Query)
			if err != nil {
				return nil, readOutput{}, toolError("read_with_scope_check", err)
			}
		}

		// Re-fetch granted scopes here rather than reusing the snapshot from
		// before Embed ran: a grant expiring or being revoked while Embed is in
		// flight would otherwise let SearchFacts run against a stale, wider scope
		// list than the subject currently holds — content disclosed after
		// revocation. Embed is synchronous/instant against the v0 Stub embedder,
		// so this window is nil today, but the real embedder this is meant to be
		// swapped for (Research track) is an external, non-trivial-latency call,
		// which is exactly when this race becomes real. This closes the window
		// between "embed" and "search"; it doesn't make the whole request atomic
		// against a grant change — full atomicity would mean pushing grant
		// membership into the retrieval SQL itself (keyed by subject, joined at
		// query time), a larger restructure of SearchFacts' signature and every
		// caller, not justified for a race this narrow today.
		grantedStrs, err = st.GrantedScopes(ctx, subject)
		if err != nil {
			return nil, readOutput{}, toolError("read_with_scope_check", err)
		}
		if missing := scope.Missing(requested, toScopes(grantedStrs)); len(missing) > 0 {
			missingStrs := fromScopes(missing)
			if err := st.LogAudit(ctx, "insufficient_scope", subject, nil, nil, nil, missingStrs); err != nil {
				return nil, readOutput{}, toolError("read_with_scope_check", err)
			}
			return nil, readOutput{Status: "insufficient_scope", MissingScopes: missingStrs}, nil
		}

		facts, err := st.SearchFacts(ctx, args.Query, queryVec, grantedStrs, limit)
		if err != nil {
			return nil, readOutput{}, toolError("read_with_scope_check", err)
		}

		out := readOutput{Status: "ok"}
		for _, f := range facts {
			out.Facts = append(out.Facts, factView{ID: f.ID, Content: f.Content, Scopes: f.Scopes})
		}
		if err := st.LogAudit(ctx, "read", subject, nil, nil, nil, grantedStrs); err != nil {
			return nil, readOutput{}, toolError("read_with_scope_check", err)
		}
		return nil, out, nil
	})
}

func toScopes(ss []string) []scope.Scope {
	out := make([]scope.Scope, len(ss))
	for i, s := range ss {
		out[i] = scope.Scope(s)
	}
	return out
}

func fromScopes(ss []scope.Scope) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}
