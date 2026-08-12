package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/agentclient"
)

type proposeWriteArgs struct {
	Content        string   `json:"content" jsonschema:"the fact being proposed, in plain text"`
	ProposedScopes []string `json:"proposed_scopes" jsonschema:"scopes this fact touches; may be overridden by the bouncer's classifier once one exists beyond the v0 passthrough stub"`
	TargetFactID   string   `json:"target_fact_id,omitempty" jsonschema:"set when this proposal updates/supersedes an existing fact by ID"`
}

type proposeWriteOutput struct {
	DiffID string `json:"diff_id"`

	// Status is the diff's staged status (e.g. "pending") on success, or
	// "RATE_LIMITED" when this subject has exceeded its propose_write rate
	// limit for the current window (store.ErrRateLimited). RATE_LIMITED is an
	// expected, structured outcome the caller is meant to act on — back off
	// and retry later — not an opaque failure, the same shape
	// read_with_scope_check already uses for status=insufficient_scope.
	Status          string  `json:"status"`
	DedupeVerdict   string  `json:"dedupe_verdict"`
	CandidateFactID *string `json:"candidate_fact_id,omitempty"`
}

// registerProposeWrite registers propose_write as a thin adapter over
// client.Propose, POST /api/agent/proposals.
//
// Old -> new mapping (the brief's required diff, for this tool):
//   - Input caps (proposed_scopes count, content length) — STILL HERE,
//     client-side, as a courtesy; agentProposeWrite re-enforces both
//     server-side regardless (agent_routes.go's agentMax* constants).
//   - The bouncer pipeline call (b.ProposeWrite: classify, embed, dedupe,
//     stage) — DELETED here, MOVED to agentProposeWrite, which calls the
//     exact same a.Bouncer.ProposeWrite this tool used to call directly. This
//     tool never touches a *bouncer.Bouncer at all now.
//   - The store.ErrRateLimited branch (audit "rate_limited", return
//     status=RATE_LIMITED with no error) — DELETED here, MOVED to
//     agentProposeWrite, which does the equivalent audit write and responds
//     with HTTP 429 carrying the same {status: RATE_LIMITED} JSON shape
//     (agentclient.Propose decodes a 429 into the same ProposeResult struct
//     as a 200 — see the TRAP note below).
//   - The bouncer.ValidationError branch (return the message verbatim) —
//     DELETED here in its original form, MOVED to agentProposeWrite, which
//     does the same errors.As check server-side and returns it as an HTTP
//     400. This tool's OWN errors.As check below (against
//     *agentclient.ValidationError, not bouncer.ValidationError) is what
//     turns that 400 back into a verbatim tool error — a different type,
//     same externally-visible behavior: the caller still sees the real
//     validation message, not a masked one.
//   - The generic masking fallback (toolError) — KEPT here, now wrapping
//     agentclient errors (ErrUnauthorized, serverError, transport failures)
//     instead of store/bouncer errors, but same "allowlist of what's safe to
//     show verbatim, mask everything else" stance.
//
// TRAP (flagged by agentclient's author, see agentclient.ProposeResult's doc
// comment): the 200 and 429 responses share one struct, discriminated only
// by Status — a 429 comes back with DiffID at its zero value, "", not a
// sentinel. The branch below checks res.Status == agentclient.StatusRateLimited
// FIRST and returns early on it, rather than ever asking "is DiffID empty?"
// to decide anything. That ordering is deliberate: it's what stops a
// rate-limited response from being read as a successful one with an empty
// diff ID.
func registerProposeWrite(s *mcp.Server, client *agentclient.Client) {
	falsePtr := false
	mcp.AddTool(s, &mcp.Tool{
		Name: "propose_write",
		Description: "Stage a proposed fact for human review. This NEVER writes memory directly — " +
			"it runs the bouncer pipeline (classify, embed, dedupe) and queues a diff that a human " +
			"must explicitly approve before it becomes a real, readable fact. The dedupe_verdict in " +
			"the response tells you what happened: novel (new fact), duplicate (matches an existing " +
			"fact exactly, will likely be rejected as redundant), or contradiction (semantically close " +
			"to an existing fact but not identical — flagged for human review rather than auto-merged). " +
			"Proposals are rate-limited per subject: if status=RATE_LIMITED comes back (no diff_id), " +
			"you've proposed too many facts too quickly — wait for the current window to pass before " +
			"retrying rather than looping on this call.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: &falsePtr, // stages a diff, never mutates committed facts
			IdempotentHint:  false,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args proposeWriteArgs) (*mcp.CallToolResult, proposeWriteOutput, error) {
		if len(args.ProposedScopes) > maxScopesPerRequest {
			return nil, proposeWriteOutput{}, fmt.Errorf("propose_write: proposed_scopes exceeds max of %d", maxScopesPerRequest)
		}
		if len(args.Content) > maxContentLength {
			return nil, proposeWriteOutput{}, fmt.Errorf("propose_write: content exceeds max length of %d", maxContentLength)
		}

		res, err := client.Propose(ctx, agentclient.ProposeRequest{
			Content:        args.Content,
			ProposedScopes: args.ProposedScopes,
			TargetFactID:   args.TargetFactID,
		})
		if err != nil {
			var verr *agentclient.ValidationError
			if errors.As(err, &verr) {
				return nil, proposeWriteOutput{}, verr
			}
			return nil, proposeWriteOutput{}, toolError("propose_write", err)
		}

		// See the TRAP note above the function: Status is checked before any
		// other field is trusted, precisely so a rate-limited response can
		// never be mistaken for a successful one just because DiffID happens
		// to be empty either way.
		if res.Status == agentclient.StatusRateLimited {
			return nil, proposeWriteOutput{Status: res.Status}, nil
		}

		return nil, proposeWriteOutput{
			DiffID:          res.DiffID,
			Status:          res.Status,
			DedupeVerdict:   res.DedupeVerdict,
			CandidateFactID: res.CandidateFactID,
		}, nil
	})
}
