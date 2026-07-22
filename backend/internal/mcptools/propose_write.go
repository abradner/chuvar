package mcptools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"memoryvault/internal/bouncer"
)

type proposeWriteArgs struct {
	Subject        string   `json:"subject" jsonschema:"the proposing agent/client identity"`
	Content        string   `json:"content" jsonschema:"the fact being proposed, in plain text"`
	ProposedScopes []string `json:"proposed_scopes" jsonschema:"scopes this fact touches; may be overridden by the bouncer's classifier once one exists beyond the v0 passthrough stub"`
	TargetFactID   string   `json:"target_fact_id,omitempty" jsonschema:"set when this proposal updates/supersedes an existing fact by ID"`
}

type proposeWriteOutput struct {
	DiffID          string  `json:"diff_id"`
	Status          string  `json:"status"`
	DedupeVerdict   string  `json:"dedupe_verdict"`
	CandidateFactID *string `json:"candidate_fact_id,omitempty"`
}

func registerProposeWrite(s *mcp.Server, b *bouncer.Bouncer) {
	falsePtr := false
	mcp.AddTool(s, &mcp.Tool{
		Name: "propose_write",
		Description: "Stage a proposed fact for human review. This NEVER writes memory directly — " +
			"it runs the bouncer pipeline (classify, embed, dedupe) and queues a diff that a human " +
			"must explicitly approve before it becomes a real, readable fact. The dedupe_verdict in " +
			"the response tells you what happened: novel (new fact), duplicate (matches an existing " +
			"fact exactly, will likely be rejected as redundant), or contradiction (semantically close " +
			"to an existing fact but not identical — flagged for human review rather than auto-merged).",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: &falsePtr, // stages a diff, never mutates committed facts
			IdempotentHint:  false,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args proposeWriteArgs) (*mcp.CallToolResult, proposeWriteOutput, error) {
		scopes := toScopes(args.ProposedScopes)

		var target *string
		if args.TargetFactID != "" {
			target = &args.TargetFactID
		}

		diff, err := b.ProposeWrite(ctx, args.Subject, args.Content, scopes, target)
		if err != nil {
			return nil, proposeWriteOutput{}, fmt.Errorf("propose_write: %w", err)
		}

		out := proposeWriteOutput{
			DiffID:          diff.ID,
			Status:          string(diff.Status),
			CandidateFactID: diff.DedupeCandidateFactID,
		}
		if diff.DedupeVerdict != nil {
			out.DedupeVerdict = string(*diff.DedupeVerdict)
		}
		return nil, out, nil
	})
}
