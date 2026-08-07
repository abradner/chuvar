package mcptools

import (
	"context"
	"fmt"
	"time"

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

// factView projects a Fact through the depth of the grant(s) that authorized
// returning it (store.SearchFacts' effectiveDepth): Content is set at "facts" or
// "full" depth, Summary at "summary" depth — never both, and Depth reports which
// one applies so a caller can tell "no summary" (empty Summary at summary depth,
// e.g. a pre-migration fact with none generated yet) apart from "not summary
// depth" (empty Summary because Content was returned instead).
//
// Provenance is "full" depth's own addition on top of "facts": the ladder was
// designed as summary → facts → *full provenance* (the init migration's
// "progressive disclosure per Notion §3"), so "full" adds a fact's provenance
// to its content rather than more content. There is exactly one gate for this,
// and it is not here: store.SearchFacts sets Fact.Provenance only when that
// row's own effective depth is "full" (see its doc comment), so copying it
// through whenever it's non-nil is the whole of this function's job —
// factView has no separate depth check to get wrong, because Provenance being
// nil already means "not full depth" for that fact. Shipping decided_by here
// discloses a human's identity (who approved the diff that produced this
// fact), which the fact's content alone never does — exactly why this is its
// own grant level rather than folded into "facts".
type factView struct {
	ID         string              `json:"id"`
	Content    string              `json:"content,omitempty"`
	Summary    string              `json:"summary,omitempty"`
	Depth      string              `json:"depth"`
	Scopes     []string            `json:"scopes"`
	Provenance *factProvenanceView `json:"provenance,omitempty"`
}

// factProvenanceView is the JSON shape of a "full"-depth fact's provenance —
// see factView's doc comment and store.FactProvenance, which this mirrors
// field-for-field (formatting times as RFC3339 strings, matching the rest of
// this package's *string time convention — see formatTimePtr).
type factProvenanceView struct {
	SourceStagedDiffID string  `json:"source_staged_diff_id"`
	DecidedBy          *string `json:"decided_by,omitempty"`
	DecidedAt          *string `json:"decided_at,omitempty"`
	SupersededBy       *string `json:"superseded_by,omitempty"`
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

		grantedDepths, err := st.GrantedScopeDepths(ctx, subject)
		if err != nil {
			return nil, readOutput{}, toolError("read_with_scope_check", err)
		}
		grantedStrs := grantedScopeStrs(grantedDepths)

		if missing := scope.Missing(requested, toScopes(grantedStrs)); len(missing) > 0 {
			missingStrs := fromScopes(missing)
			if err := st.LogAudit(ctx, "insufficient_scope", subject, nil, nil, nil, nil, missingStrs); err != nil {
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

		// Re-fetch granted scope depths here rather than reusing the snapshot
		// from before Embed ran: a grant expiring, being revoked, or changing
		// depth while Embed is in flight would otherwise let SearchFacts run
		// against a stale, wider/deeper scope list than the subject currently
		// holds — content disclosed after revocation or a depth downgrade.
		// Embed is synchronous/instant against the v0 Stub embedder, so this
		// window is nil today, but the real embedder this is meant to be
		// swapped for (Research track) is an external, non-trivial-latency
		// call, which is exactly when this race becomes real. This closes the
		// window between "embed" and "search"; it doesn't make the whole
		// request atomic against a grant change — full atomicity would mean
		// pushing grant membership into the retrieval SQL itself (keyed by
		// subject, joined at query time), a larger restructure of SearchFacts'
		// signature and every caller, not justified for a race this narrow
		// today.
		grantedDepths, err = st.GrantedScopeDepths(ctx, subject)
		if err != nil {
			return nil, readOutput{}, toolError("read_with_scope_check", err)
		}
		grantedStrs = grantedScopeStrs(grantedDepths)
		if missing := scope.Missing(requested, toScopes(grantedStrs)); len(missing) > 0 {
			missingStrs := fromScopes(missing)
			if err := st.LogAudit(ctx, "insufficient_scope", subject, nil, nil, nil, nil, missingStrs); err != nil {
				return nil, readOutput{}, toolError("read_with_scope_check", err)
			}
			return nil, readOutput{Status: "insufficient_scope", MissingScopes: missingStrs}, nil
		}

		facts, err := st.SearchFacts(ctx, args.Query, queryVec, grantedDepths, limit)
		if err != nil {
			return nil, readOutput{}, toolError("read_with_scope_check", err)
		}

		out := readOutput{Status: "ok"}
		for _, f := range facts {
			fv := factView{ID: f.ID, Content: f.Content, Summary: f.Summary, Depth: f.Depth, Scopes: f.Scopes}
			if f.Provenance != nil {
				p := f.Provenance
				fv.Provenance = &factProvenanceView{
					SourceStagedDiffID: p.SourceStagedDiffID,
					DecidedBy:          p.DecidedBy,
					DecidedAt:          formatTimePtr(p.DecidedAt),
					SupersededBy:       p.SupersededBy,
					ValidAt:            f.ValidAt.Format(time.RFC3339),
					InvalidAt:          formatTimePtr(p.InvalidAt),
					ExpiredAt:          formatTimePtr(p.ExpiredAt),
				}
			}
			out.Facts = append(out.Facts, fv)
		}
		if err := st.LogAudit(ctx, "read", subject, nil, nil, nil, nil, grantedStrs); err != nil {
			return nil, readOutput{}, toolError("read_with_scope_check", err)
		}
		return nil, out, nil
	})
}

// grantedScopeStrs discards the depth half of each pair and dedupes, for the
// scope.Missing visibility check and audit logging — both only ever needed
// which scopes were granted, not at what depth (depth only matters once
// SearchFacts runs). Deduping matters here specifically because
// GrantedScopeDepths is DISTINCT on (scope, depth), not scope alone: a
// subject holding two active grants over the same scope at different depths
// produces two rows with an identical Scope, which would otherwise duplicate
// that scope in the audit log's recorded scopes list. Found in review.
func grantedScopeStrs(granted []store.GrantedScope) []string {
	seen := make(map[string]struct{}, len(granted))
	out := make([]string, 0, len(granted))
	for _, g := range granted {
		if _, ok := seen[g.Scope]; ok {
			continue
		}
		seen[g.Scope] = struct{}{}
		out = append(out, g.Scope)
	}
	return out
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
