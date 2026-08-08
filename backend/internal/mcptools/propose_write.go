package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abradner/chuvar/backend/internal/bouncer"
	"github.com/abradner/chuvar/backend/internal/store"
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

func registerProposeWrite(s *mcp.Server, subject string, b *bouncer.Bouncer) {
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

		scopes := toScopes(args.ProposedScopes)

		var target *string
		if args.TargetFactID != "" {
			target = &args.TargetFactID
		}

		diff, err := b.ProposeWrite(ctx, subject, args.Content, scopes, target)
		if err != nil {
			if errors.Is(err, store.ErrRateLimited) {
				// Distinguishable from every other bouncer/store failure below on
				// purpose (CLAUDE.md's ticket calls for "RATE_LIMITED as a signal
				// rather than backpressure") — returned as a structured status with
				// no tool error, not masked by toolError, since there's nothing
				// sensitive in "you're proposing too fast" that toolError's masking
				// exists to protect.
				//
				// Audited before responding, same as insufficient_scope in
				// read_with_scope_check.go: a tripwire that reports only to the
				// adversary who tripped it is not a tripwire. The counter row alone
				// is lossy evidence (limit+1 and a 10,000-request flood look the
				// same after the window rolls), so each denial gets its own
				// attributable row — and like the insufficient_scope sibling, a
				// failed audit write fails the response rather than being dropped.
				if auditErr := b.Store.LogAudit(ctx, "rate_limited", subject, nil, nil, nil, nil, nil, nil); auditErr != nil {
					return nil, proposeWriteOutput{}, toolError("propose_write", auditErr)
				}
				return nil, proposeWriteOutput{Status: "RATE_LIMITED"}, nil
			}
			// bouncer.ProposeWrite's errors mix genuine input-validation failures
			// (safe and useful to show the agent verbatim, e.g. a malformed scope —
			// it can self-correct and retry) with wrapped store/DB errors (not
			// safe — could contain raw driver text). errors.As against
			// bouncer.ValidationError is how those are told apart: only errors
			// ProposeWrite positively constructed as that type are returned
			// verbatim; everything else — including anything unrecognized — still
			// goes through toolError's generic masking. Fail closed: this is an
			// allowlist, not a denylist.
			var verr *bouncer.ValidationError
			if errors.As(err, &verr) {
				return nil, proposeWriteOutput{}, verr
			}
			return nil, proposeWriteOutput{}, toolError("propose_write", err)
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
