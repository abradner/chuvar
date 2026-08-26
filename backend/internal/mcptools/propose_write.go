package mcptools

import (
	"context"
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
	// limit for the current window. RATE_LIMITED is an expected, structured
	// outcome the caller is meant to act on — back off and retry later — not
	// an opaque failure, the same shape read_with_scope_check already uses
	// for status=insufficient_scope.
	Status string `json:"status"`
	// DedupeVerdict/CandidateFactID carry the #83 dedupe-disclosure redaction,
	// but post-cutover that redaction happens server-side: the agent endpoint
	// (internal/api/agentProposeWrite) builds its response from the store's
	// DedupeDisclosure, not the staged diff's always-true fields, so a caller
	// whose granted depth over the matched fact is "summary" already receives
	// DedupeVerdict="needs_review" and no CandidateFactID over the wire. This
	// client forwards the server's values verbatim; it must NOT reconstruct
	// them from anything else (there's nothing else here to reconstruct from —
	// mcpserver holds no store), which keeps the redaction a single
	// server-side chokepoint (issue #83, principle 7).
	DedupeVerdict   string  `json:"dedupe_verdict"`
	CandidateFactID *string `json:"candidate_fact_id,omitempty"`
}

// registerProposeWrite registers propose_write as a thin adapter over
// client.Propose: marshal args into an agentclient.ProposeRequest, call the
// agent API, map the response onto proposeWriteOutput. The bouncer pipeline
// (classify, embed, dedupe) this tool used to run in-process via *bouncer.Bouncer
// now runs entirely server-side, behind agentProposeWrite
// (internal/api/agent_routes.go) — this function no longer imports
// internal/bouncer or internal/store at all.
//
// ⚠️ The trap this cutover was flagged for: agentclient.ProposeResult is ONE
// struct shared by both the 200 (successful proposal) and the 429
// (rate-limited) response — Client.Propose decodes a 429 into the exact same
// ProposeResult shape as a 200 (see that method's doc comment), with
// err == nil either way. DiffID/DedupeVerdict/CandidateFactID are only
// meaningful when res.Status != agentclient.StatusRateLimited; a naive
// "always trust DiffID" read would report a rate-limited proposal as a
// successful one with an empty diff ID. res.Status is checked below before
// any other field on res is read, preserving propose_write's original
// three-way outcome exactly: rate-limited status (no diff_id), a validation
// error shown verbatim (mapClientError's *agentclient.ValidationError case),
// or everything else masked (mapClientError's toolError fallback).
func registerProposeWrite(s *mcp.Server, client *agentclient.Client) {
	falsePtr := false
	mcp.AddTool(s, &mcp.Tool{
		Name: "propose_write",
		Description: "Stage a proposed fact for human review. This NEVER writes memory directly — " +
			"it runs the bouncer pipeline (classify, embed, dedupe) and queues a diff that a human " +
			"must explicitly approve before it becomes a real, readable fact. The dedupe_verdict in " +
			"the response tells you what happened: novel (new fact), duplicate (matches an existing " +
			"fact exactly, will likely be rejected as redundant), contradiction (semantically close " +
			"to an existing fact but not identical — flagged for human review rather than auto-merged), " +
			"or needs_review (something close enough to flag exists, but you don't hold enough depth on " +
			"the matched fact to be told which of the above applies or its fact ID — the exact/near " +
			"distinction and the ID are withheld the same way a summary-depth read would redact that " +
			"fact's content; this is expected, not an error). " +
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
			return nil, proposeWriteOutput{}, mapClientError("propose_write", err)
		}

		// See the trap warning in this function's doc comment: Status is
		// checked before DiffID/DedupeVerdict/CandidateFactID are trusted.
		if res.Status == agentclient.StatusRateLimited {
			return nil, proposeWriteOutput{Status: agentclient.StatusRateLimited}, nil
		}

		// res.DedupeVerdict/res.CandidateFactID are already the #83-redacted
		// disclosure — the agent endpoint applied store.disclosureForProposer
		// server-side before responding (see proposeWriteOutput's field
		// comment). Forward them verbatim; the redaction is not this client's
		// to reconstruct.
		return nil, proposeWriteOutput{
			DiffID:          res.DiffID,
			Status:          res.Status,
			DedupeVerdict:   res.DedupeVerdict,
			CandidateFactID: res.CandidateFactID,
		}, nil
	})
}
